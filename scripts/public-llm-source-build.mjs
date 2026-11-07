// Offline COPY-closure qualification. No Docker, dotenv, dependency install or network.
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname, relative } from 'node:path';
import { createRequire, isBuiltin } from 'node:module';
import { spawnSync } from 'node:child_process';
// Kept inside the historically audited execution closure; the new descriptor module re-exports this contract.
// Pure v6 deployment contract. No environment, secret, filesystem or Docker reads.
import { isDeepStrictEqual as equal } from 'node:util';

export const OPENAI_DEPLOYMENT = Object.freeze({
  version: 6, provider: 'OpenAI', model: 'gpt-5.4-mini-2026-03-17',
  configName: 'openai-deployment.json',
  bootstrap: 'server/deploy/openai-secret-bootstrap.mjs',
  entrypoint: Object.freeze(['/usr/local/bin/node', '--disable-warning=ExperimentalWarning', '/app/server/deploy/openai-secret-bootstrap.mjs']),
  command: Object.freeze(['node', '--import', 'tsx', 'src/oci/public-image.main.ts']),
  volumeKey: 'openai-secrets', mount: '/run/openai-secrets', target: '/run/openai-secrets/server.env',
  gatewayCommand: Object.freeze(['python', '-I', 'openai.py', '--serve']),
  networks: Object.freeze(['openai_internal', 'openai_uplink']),
});
export const PUBLIC_IMAGE_OPERATIONS = 'public-images-v2';
export const PUBLIC_IMAGE_OPERATIONS_ACK = '--ack-public-worker-egress-upgrade';
export const PUBLIC_IMAGE_LOGGING = Object.freeze({ driver: 'json-file', options: Object.freeze({ 'max-size': '10m', 'max-file': '3' }) });
export const PUBLIC_IMAGE_OPERATION_ROLES = Object.freeze(['api', 'worker', 'web', 'egress', 'llm-egress', 'openai-egress']);
export const PUBLIC_IMAGE_EGRESS_COMMAND = Object.freeze(['python', '-I', 'proxy.py', '--public-images-v2']);

export const openAiSafe = ok => { if (!ok) throw Error('PUBLIC OpenAI v6 refused/HOLD; details withheld.'); };
const safe = openAiSafe;
const keys = (x, names) => {
  safe(x && Object.getPrototypeOf(x) === Object.prototype && !Object.getOwnPropertySymbols(x).length);
  const entries = Object.getOwnPropertyDescriptors(x);
  safe(Object.values(entries).every(d => d.enumerable && Object.hasOwn(d, 'value')));
  safe(equal(Object.keys(entries).sort(), [...names].sort()));
};
const revision = x => typeof x === 'string' && x !== 'undecided' && /^[A-Za-z0-9._-]{1,80}$/.test(x);
export const openAiVolumeName = x => x === 'openai-secrets';

// An embedded historical identity, never a recursive v6 or a reinterpreted v1-v5.
export function openAiRouterSelection(value) {
  const version = Object.getOwnPropertyDescriptor(value ?? {}, 'version')?.value;
  safe(Number.isInteger(version) && version >= 1 && version <= 5);
  keys(value, ['version', 'keyVolume', ...(version >= 2 ? ['timing'] : []), ...(version >= 3 ? ['profile'] : [])]);
  safe(value.keyVolume === null || typeof value.keyVolume === 'string' && /^diplom-public-8081-llm-key-[a-f0-9]{32}$/.test(value.keyVolume));
  if (value.version >= 2) safe(value.timing === 'public-8081-90s-v1');
  if (value.version >= 3) safe(value.profile === ({ 3: 'public-8081-nvidia-v1', 4: 'public-8081-dots-v1', 5: 'public-8081-remediation-4k-v1' })[value.version]);
  return Object.freeze({ version: value.version, keyVolume: value.keyVolume,
    ...(value.version >= 2 ? { timing: value.timing } : {}), ...(value.version >= 3 ? { profile: value.profile } : {}) });
}

const fixed = Object.freeze({ LLM_PROVIDER: 'openai', OPENAI_MODEL: OPENAI_DEPLOYMENT.model,
  OPENAI_ROUTING_APPROVED: 'true', OPENAI_RETENTION: 'no-training', LLM_QUOTA_ENABLED: 'true', LLM_QUOTA_WINDOW: 'utc-day' });
// Technical ceilings mirror the server parsers; none are defaults or chosen spend limits.
const numeric = Object.freeze({
  OPENAI_INPUT_PRICE_MICROS_PER_MILLION: [1, 1_000_000_000], OPENAI_OUTPUT_PRICE_MICROS_PER_MILLION: [1, 1_000_000_000],
  OPENAI_TIMEOUT_MS: [1, 90_000], OPENAI_REQUEST_BYTES: [1, 262_144], OPENAI_RESPONSE_BYTES: [1, 65_536],
  OPENAI_INPUT_TOKENS: [1, 65_536], OPENAI_OUTPUT_TOKENS: [1, 4096], OPENAI_FINDINGS: [1, 1000], OPENAI_MAX_CONCURRENT: [1, 8],
  LLM_QUOTA_USER_INPUT: [1, 1e9], LLM_QUOTA_USER_OUTPUT: [1, 1e9], LLM_QUOTA_SCAN_INPUT: [1, 1e9], LLM_QUOTA_SCAN_OUTPUT: [1, 1e9],
  LLM_QUOTA_WARNING_PERCENT: [80, 80], LLM_QUOTA_REQUEST_INPUT: [1025, 65_536], LLM_QUOTA_OBSERVATION_TOKENS: [65_536, 1_048_576],
  LLM_QUOTA_OBSERVATION_COST_MICROS: [1, 2_097_152_000], LLM_QUOTA_RECEIPT_MS: [30_000, 300_000],
  LLM_QUOTA_REPLAY_DAYS: [7, 7], LLM_QUOTA_MAX_ROWS: [2, 100_000], LLM_QUOTA_DB_BYTES: [1_048_576, 67_108_864],
  LLM_QUOTA_DISK_HEADROOM_BYTES: [134_217_728, 268_435_456], LLM_QUOTA_BUSY_MS: [1, 1000], LLM_QUOTA_CLEANUP_BATCH: [1, 256],
});
const budgetNames = ['OPENAI_REQUEST_BUDGET_MICROS', 'OPENAI_USER_BUDGET_MICROS', 'OPENAI_SCAN_BUDGET_MICROS'];
const costNames = ['LLM_QUOTA_USER_COST_USD', 'LLM_QUOTA_SCAN_COST_USD'];
const lifetimeCostName = 'LLM_QUOTA_LIFETIME_USER_COST_MICROS';
function integer(text, min, max) {
  safe(typeof text === 'string' && /^(?:0|[1-9][0-9]{0,15})$/.test(text));
  const n = Number(text); safe(Number.isSafeInteger(n) && n >= min && n <= max); return n;
}
function dollars(text) {
  safe(typeof text === 'string' && /^(?:0|1)(?:\.[0-9]{1,6})?$/.test(text));
  const [whole, fraction = ''] = text.split('.');
  const n = Number(whole) * 1_000_000 + Number(fraction.padEnd(6, '0'));
  safe(n > 0 && n <= 1_000_000); return n;
}
export function validateOpenAiDeployment(value) {
  keys(value, ['version', 'provider', 'keyVolume', 'openrouter', 'monetaryLimit', 'environment', 'credentialVolume',
    ...(Object.hasOwn(value ?? {}, 'operations') ? ['operations'] : [])]);
  safe(!Object.hasOwn(value, 'operations') || value.operations === PUBLIC_IMAGE_OPERATIONS);
  safe(value.version === 6 && value.provider === 'OpenAI' && ['capped', 'uncapped'].includes(value.monetaryLimit));
  const openrouter = openAiRouterSelection(value.openrouter);
  safe(value.keyVolume === openrouter.keyVolume && (value.credentialVolume === null || openAiVolumeName(value.credentialVolume)));
  const e = value.environment, mode = value.monetaryLimit;
  const lifetime = mode === 'uncapped' && Object.hasOwn(e ?? {}, lifetimeCostName);
  keys(e, [...Object.keys(fixed), ...Object.keys(numeric), 'OPENAI_ENABLED', 'OPENAI_POLICY_REVISION', 'OPENAI_ACCOUNTING_REVISION',
    'LLM_QUOTA_REVISION', 'OPENAI_MONETARY_LIMIT', 'LLM_QUOTA_MONETARY_LIMIT', ...(mode === 'capped' ? [...budgetNames, ...costNames] : []),
    ...(lifetime ? [lifetimeCostName] : [])]);
  // Independent account-lifetime cap, not a daily or per-request monetary budget.
  if (lifetime) integer(e[lifetimeCostName], 1, 1_000_000_000);
  safe(Object.entries(fixed).every(([k, v]) => e[k] === v) && ['true', 'false'].includes(e.OPENAI_ENABLED));
  safe(e.OPENAI_ENABLED !== 'true' || value.credentialVolume !== null);
  safe(['OPENAI_POLICY_REVISION', 'OPENAI_ACCOUNTING_REVISION', 'LLM_QUOTA_REVISION'].every(k => revision(e[k])));
  safe(e.OPENAI_MONETARY_LIMIT === mode && e.LLM_QUOTA_MONETARY_LIMIT === mode);
  const n = Object.fromEntries(Object.entries(numeric).map(([key, [min, max]]) => [key, integer(e[key], min, max)]));
  safe(n.LLM_QUOTA_DB_BYTES % 4096 === 0 && n.LLM_QUOTA_REQUEST_INPUT >= n.OPENAI_INPUT_TOKENS &&
    n.LLM_QUOTA_RECEIPT_MS > n.OPENAI_TIMEOUT_MS && n.LLM_QUOTA_OBSERVATION_TOKENS >= Math.max(n.OPENAI_INPUT_TOKENS, n.OPENAI_OUTPUT_TOKENS));
  if (mode === 'capped') {
    const [request, user, scan] = budgetNames.map(k => integer(e[k], 1, 1_000_000));
    safe(Math.min(user, scan) >= request && dollars(e.LLM_QUOTA_USER_COST_USD) === user && dollars(e.LLM_QUOTA_SCAN_COST_USD) === scan &&
      n.LLM_QUOTA_OBSERVATION_COST_MICROS >= request);
  }
  const upperCost = (BigInt(n.OPENAI_INPUT_TOKENS) * BigInt(n.OPENAI_INPUT_PRICE_MICROS_PER_MILLION) +
    BigInt(n.OPENAI_OUTPUT_TOKENS) * BigInt(n.OPENAI_OUTPUT_PRICE_MICROS_PER_MILLION) + 999999n) / 1000000n;
  if (mode === 'uncapped') safe(upperCost <= BigInt(n.LLM_QUOTA_OBSERVATION_COST_MICROS));
  // Canonical output contains no unknown field, key value, path override or secret hash.
  return Object.freeze({ version: 6, provider: 'OpenAI', keyVolume: openrouter.keyVolume, openrouter,
    monetaryLimit: mode, environment: Object.freeze(Object.fromEntries(Object.keys(e).sort().map(k => [k, e[k]]))), credentialVolume: value.credentialVolume,
        ...(value.operations ? { operations: value.operations } : {}) });
}
export function validateOpenAiBuildDeployment(value) {
  keys(value, ['prior', 'next']);
  const priorVersion = Object.getOwnPropertyDescriptor(value.prior ?? {}, 'version')?.value;
  const prior = priorVersion === 6 ? validateOpenAiDeployment(value.prior) : openAiRouterSelection(value.prior);
  const next = validateOpenAiDeployment(value.next);
  safe(equal(next.openrouter, prior.version === 6 ? prior.openrouter : prior));
  safe(prior.version !== 6 || !prior.credentialVolume || prior.credentialVolume === next.credentialVolume);
  safe(!prior.operations || prior.operations === next.operations);
  safe(!next.operations || prior.version === 6);
  return { prior, next };
}

// The immutable operator descriptor need not be rewritten for an operations-only
// upgrade. Publication records the selected revision; later normal up preserves it.
export function selectOpenAiOperations(descriptor, prior, upgrade = false) {
  const next = validateOpenAiDeployment(descriptor);
  safe(typeof upgrade === 'boolean');
  if (upgrade) safe(prior?.version === 6);
  if (next.operations && !prior?.operations) safe(upgrade);
  const operations = upgrade || prior?.operations || next.operations ? PUBLIC_IMAGE_OPERATIONS : null;
  const result = validateOpenAiDeployment({ ...next, ...(operations ? { operations } : {}) });
  validateOpenAiBuildDeployment({ prior, next: result });
  return result;
}

export function validateOpenAiVolume(value, selection) {
  const s = validateOpenAiDeployment(selection);
  safe(s.credentialVolume !== null && value?.Name === s.credentialVolume && value.Driver === 'local' && value.Scope === 'local' &&
    typeof value.Mountpoint === 'string' && value.Mountpoint.startsWith('/') && !/[\x00-\x1f\x7f]/.test(value.Mountpoint) &&
    equal(value.Options ?? {}, {}));
  keys(value.Labels, ['org.diplom.openai-secret', 'org.diplom.openai-secret.claim']);
  safe(value.Labels['org.diplom.openai-secret'] === 'v1' && /^[a-f0-9]{32}$/.test(value.Labels['org.diplom.openai-secret.claim']));
}
export function openAiEnvironment(selection, routerEnvironment) {
  const s = validateOpenAiDeployment(selection);
  // Replace the WHOLE quota family, including legacy dollar observation/cost fields.
  return { ...Object.fromEntries(Object.entries(routerEnvironment).filter(([k]) => !k.startsWith('LLM_QUOTA_'))), ...s.environment };
}
export function assertNoOpenAiDockerSecret(config) {
  safe(Array.isArray(config?.Env) && !config.Env.some(v => typeof v !== 'string' || /^OPENAI_API_KEY(?:=|$)/.test(v)));
}


// Separate v6 execution authority. Never imported by or added to frozen recovery's allowlist.
const OPENAI_EXECUTION_MODULES = Object.freeze([
  'scripts/local-stand.mjs', 'scripts/public-current-backup-transfer.mjs', 'scripts/public-cve-bridge-capacity.mjs',
  'scripts/public-cve-bridge-runtime.mjs', 'scripts/public-cve-bridge.mjs', 'scripts/public-cve-provision.mjs',
  'scripts/public-image-stand-profile.mjs', 'scripts/public-image-stand.mjs', 'scripts/public-llm-build-continuation.mjs',
  'scripts/public-llm-deployment-catalog.mjs', 'scripts/public-llm-source-build.mjs', 'scripts/public-llm-stand.mjs',
  'scripts/public-llm-initialize-continuation.mjs', 'scripts/public-llm-rollout-completion.mjs',
  'scripts/public-refresh-cve-preservation.mjs', 'scripts/refresh-local-cve.mjs', 'scripts/refresh-public-cve.mjs',
  'scripts/setup-local-cve.mjs', 'server/deploy/trust/fetch-db-layer.mjs',
  'scripts/public-openai-descriptor.mjs', 'scripts/public-openai-deployment.mjs', 'scripts/public-openai-config.mjs',
  OPENAI_DEPLOYMENT.bootstrap,
]);
const OPENAI_EXECUTION_ENTRIES = Object.freeze(['scripts/public-llm-stand.mjs', 'scripts/public-openai-config.mjs',
  'scripts/public-openai-deployment.mjs', OPENAI_DEPLOYMENT.bootstrap]);

// readSource must capture/fence the exact public bytes it returns. The walker does
// not execute discovered modules. Computed imports and undeclared dependencies refuse.
export function discoverOpenAiExecutionClosure(root, readSource) {
  safe(resolve(root) === root && typeof readSource === 'function');
  const require = createRequire(import.meta.url), ts = require('typescript');
  const permitted = new Set(OPENAI_EXECUTION_MODULES), modules = new Set(), edges = new Set(), todo = [...OPENAI_EXECUTION_ENTRIES];
  let bytes = 0, sites = 0;
  while (todo.length) {
    const name = todo.shift(); if (modules.has(name)) continue;
    safe(permitted.has(name) && modules.size < 32);
    const text = readSource(name); safe(typeof text === 'string' && Buffer.byteLength(text) <= 1024 ** 2);
    bytes += Buffer.byteLength(text); safe(bytes <= 4 * 1024 ** 2);
    const source = ts.createSourceFile(name, text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    safe(source.parseDiagnostics.length === 0); modules.add(name);
    const requireNames = new Set(['require', 'requireApi']), createNames = new Set(['createRequire']), declarations = [];
    const collect = node => {
      if (ts.isImportDeclaration(node) && node.moduleSpecifier.text === 'node:module' &&
          node.importClause?.namedBindings && ts.isNamedImports(node.importClause.namedBindings)) {
        for (const e of node.importClause.namedBindings.elements) if ((e.propertyName ?? e.name).text === 'createRequire') createNames.add(e.name.text);
      }
      if (ts.isVariableDeclaration(node) && ts.isIdentifier(node.name) && node.initializer) declarations.push(node);
      ts.forEachChild(node, collect);
    };
    collect(source);
    for (let changed = true, rounds = 0; changed;) {
      safe(++rounds <= 32); changed = false;
      for (const d of declarations) {
        const e = d.initializer;
        if (!requireNames.has(d.name.text) && (ts.isIdentifier(e) && requireNames.has(e.text) ||
            ts.isCallExpression(e) && ts.isIdentifier(e.expression) && createNames.has(e.expression.text))) {
          requireNames.add(d.name.text); changed = true;
        }
      }
    }
    const dependency = specifier => {
      safe(++sites <= 512);
      if (specifier.startsWith('.')) {
        safe(/^(?:\.\/|\.\.\/)[a-zA-Z0-9_./-]+\.mjs$/.test(specifier));
        const target = relative(root, resolve(dirname(join(root, name)), specifier));
        safe(permitted.has(target)); edges.add(name + ' -> ' + target); safe(edges.size <= 256); todo.push(target);
      } else safe(isBuiltin(specifier) || ['typescript', 'typescript/bin/tsc', 'better-sqlite3'].includes(specifier));
    };
    const visit = node => {
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
        safe(ts.isStringLiteralLike(node.moduleSpecifier)); dependency(node.moduleSpecifier.text);
      }
      if (ts.isCallExpression(node)) {
        const e = node.expression;
        const loader = e.kind === ts.SyntaxKind.ImportKeyword || ts.isIdentifier(e) && requireNames.has(e.text) ||
          ts.isCallExpression(e) && ts.isIdentifier(e.expression) && createNames.has(e.expression.text) ||
          ts.isPropertyAccessExpression(e) && e.name.text === 'resolve' && ts.isIdentifier(e.expression) && requireNames.has(e.expression.text);
        if (loader) { safe(node.arguments.length === 1 && ts.isStringLiteralLike(node.arguments[0])); dependency(node.arguments[0].text); }
      }
      ts.forEachChild(node, visit);
    };
    visit(source);
  }
  return { entries: [...OPENAI_EXECUTION_ENTRIES], modules: [...modules].sort(), edges: [...edges].sort() };
}

// The only writable DB here is a disposable private copy of an immutable capture.
// No provider/runtime factory, bootstrap, live mount, reset or initialization path.
export function checkOpenAiQuotaSnapshot(root, { selection, snapshotPath }) {
  const env = validateOpenAiDeployment(selection).environment;
  safe(resolve(root) === root && fs.realpathSync(root) === root && resolve(snapshotPath) === snapshotPath &&
    fs.realpathSync(dirname(snapshotPath)) === dirname(snapshotPath));
  const stamp = s => [s.dev, s.ino, s.uid, s.mode, s.nlink, s.size, s.mtimeMs, s.ctimeMs];
  const initial = fs.lstatSync(snapshotPath);
  safe(initial.isFile() && !initial.isSymbolicLink() && initial.nlink === 1 && initial.uid === process.getuid() &&
    (initial.mode & 0o7777) === 0o600 && initial.size > 0 && initial.size <= 64 * 1024 ** 2);
  const fd = fs.openSync(snapshotPath, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  let temp;
  try {
    const read = () => {
      safe(equal(stamp(fs.fstatSync(fd)), stamp(initial)) && equal(stamp(fs.lstatSync(snapshotPath)), stamp(initial)));
      const b = Buffer.alloc(initial.size + 1); let size = 0;
      while (size < b.length) { const n = fs.readSync(fd, b, size, b.length - size, size); if (!n) break; size += n; }
      safe(size === initial.size && equal(stamp(fs.fstatSync(fd)), stamp(initial)) && equal(stamp(fs.lstatSync(snapshotPath)), stamp(initial)));
      for (const suffix of ['-journal', '-wal', '-shm']) safe(!fs.existsSync(snapshotPath + suffix));
      return b.subarray(0, size);
    };
    const bytes = read();
    temp = fs.realpathSync(fs.mkdtempSync(join(tmpdir(), 'public-openai-quota-')));
    fs.chmodSync(temp, 0o700);
    const copy = join(temp, 'llm-usage.sqlite'); fs.writeFileSync(copy, bytes, { flag: 'wx', mode: 0o600 });
    const code = `import fs from 'node:fs';
      import {QuotaLedger} from './src/llm/quota-ledger.ts';
      import {quotaPolicyFromEnvironment} from './src/llm/quota-policy.ts';
      try{const {path,env}=JSON.parse(fs.readFileSync(0,'utf8'));
        const policy=quotaPolicyFromEnvironment(env);if(!policy)throw Error();
        const ledger=new QuotaLedger(path,policy,Date.now,false);ledger.close();
      }catch{process.exitCode=70;}`;
    const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
      cwd: join(root, 'server/api'), env: { PATH: process.env.PATH }, input: JSON.stringify({ path: copy, env }),
      encoding: 'utf8', timeout: 30000, maxBuffer: 65536,
    });
    safe(read().equals(bytes));
    safe(result.status === 0 && result.signal === null && !result.error && result.stdout === '');
    return { compatible: true };
  } catch { throw Error('PUBLIC OpenAI quota snapshot incompatible/HOLD; details withheld.'); }
  finally { fs.closeSync(fd); if (temp) fs.rmSync(temp, { recursive: true, force: true }); }
}

export function checkPublicLlmSourceBuild(root, { openai = null } = {}) {
  const selection = openai === null ? null : validateOpenAiDeployment(openai);
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
    if (selection) {
      // Match the v6 API COPY closure, not repository-wide tests or an ambient .env.
      for (const path of ['server/api/src', 'server/api/tsconfig.json', 'server/runtime/src', OPENAI_DEPLOYMENT.bootstrap,
        'server/deploy/openai-api.Dockerfile', 'server/deploy/openai-secret-init.py', 'scripts/openai-secret-provision.py',
        'server/deploy/gateway/openai.Dockerfile', 'server/deploy/gateway/openai.py', 'server/deploy/gateway/proxy.py']) {
        const stat = fs.lstatSync(join(root, path));
        if (stat.isSymbolicLink() || !(stat.isFile() || stat.isDirectory())) refuse('PUBLIC_OPENAI_SOURCE_REJECTED');
        fs.mkdirSync(dirname(join(temp, path)), { recursive: true });
        fs.cpSync(join(root, path), join(temp, path), { recursive: true, dereference: false });
      }
      fs.symlinkSync(join(root, 'server/api/node_modules'), join(temp, 'server/api/node_modules'), 'dir');
      fs.writeFileSync(join(temp, 'server/api/tsconfig.public-openai.json'), JSON.stringify({ extends: './tsconfig.json',
        files: ['src/oci/public-image.main.ts', ...(selection.operations ? ['src/worker/public-image-worker.main.ts'] : [])], include: [] }));
      if (run([require.resolve('typescript/bin/tsc'), '--project', 'server/api/tsconfig.public-openai.json']).status !== 0)
        refuse('PUBLIC_OPENAI_TYPESCRIPT_REJECTED');
      if (run(['--check', OPENAI_DEPLOYMENT.bootstrap]).status !== 0) refuse('PUBLIC_OPENAI_BOOTSTRAP_REJECTED');

      const code = `import fs from 'node:fs';
        import {readOpenAiEnvironment} from './src/llm/openai-environment.ts';
        import {quotaPolicyFromEnvironment} from './src/llm/quota-policy.ts';
        import {createOpenAiRuntime} from './src/llm/provider-runtime.ts';
        import {OPENAI_PROMPTS} from './src/llm/openai-prompts.ts';
                import {PUBLIC_IMAGE_RESOURCE_POLICY, PUBLIC_IMAGE_CHECKS_VERSION, PUBLIC_IMAGE_LIMITS} from './src/oci/public-image-policy.ts';
                import {publicResourceEnvelope} from './src/worker/worker-runtime.ts';
                import * as zlib from 'node:zlib';
        import * as bootstrap from '../deploy/openai-secret-bootstrap.mjs';
        const expected=${JSON.stringify(OPENAI_DEPLOYMENT)};
        if(JSON.stringify(bootstrap.API_ENTRYPOINT)!==JSON.stringify(expected.entrypoint)||
          JSON.stringify(bootstrap.API_COMMAND)!==JSON.stringify(expected.command)||bootstrap.SECRET_PATH!==expected.target||
          bootstrap.SECRET_VOLUME!==expected.volumeKey)throw Error('bootstrap-contract');
        const env=JSON.parse(fs.readFileSync(0,'utf8'));
        const config=readOpenAiEnvironment(OPENAI_PROMPTS,{...env,OPENAI_ENABLED:'true'});
        const quota=quotaPolicyFromEnvironment(env);
        if(!config||!quota||!createOpenAiRuntime(config,quota,()=>{throw Error('offline-provider-forbidden');}))throw Error('configuration');
                const operations=${JSON.stringify(selection.operations ?? null)};
                if(operations){
                  if(PUBLIC_IMAGE_RESOURCE_POLICY!=='public-hub-resources-v2'||PUBLIC_IMAGE_CHECKS_VERSION!=='trivy-0.69.3-public-archive-v2'||
                    typeof zlib.createZstdDecompress!=='function')throw Error('public-image-runtime');
                  const expected={compressedLayer:256*1024**2,compressedTotal:768*1024**2,wireBytes:800*1024**2,
                    expandedLayer:512*1024**2,expandedTotal:1024**3,scratchBytes:2*1024**3,deadlineMs:180000};
                  if(Object.entries(expected).some(([key,value])=>PUBLIC_IMAGE_LIMITS[key]!==value))throw Error('public-image-budget');
                  if(!publicResourceEnvelope(name=>({'memory.max':'4294967296','memory.swap.max':'0','cpu.max':'100000 100000','pids.max':'128'})[name],
                    ()=>({info:{isDirectory:()=>true,isSymbolicLink:()=>false},fs:{type:0x01021994,blocks:2304*256,bsize:4096}})))throw Error('public-image-envelope');
                }else if(PUBLIC_IMAGE_RESOURCE_POLICY!=='public-hub-resources-v1')throw Error('worker-upgrade-ack-required');`;
      const result = spawnSync(process.execPath, ['--import', 'tsx', '--input-type=module', '-e', code], {
        cwd: join(temp, 'server/api'), env: { PATH: process.env.PATH }, input: JSON.stringify(selection.environment),
        encoding: 'utf8', timeout: 30000, maxBuffer: 2 * 1024 ** 2 });
      if (result.status !== 0) refuse('PUBLIC_OPENAI_RUNTIME_CONFIGURATION_REJECTED');
    }
    return { typescript: true, bundle: true, docker: false, ...(selection ? { openai: true } : {}) };
  } finally { fs.rmSync(temp, { recursive: true, force: true }); }
}
