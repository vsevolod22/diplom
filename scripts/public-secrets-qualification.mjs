import { spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { chmodSync, cpSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const PIN = 'sha256:d8c3888125737a5059d2b42d8c8f98cf7a41677aff17838e8bc30546eccb9d0b';
export const WORKER = 'dip-public-images-worker-1';
export const COMMAND = ['node', '--import', 'tsx', 'src/worker/public-image-worker.main.ts'];
const allowed = value => { if (!value) throw new Error('Qualification guard failed'); };
export function validateWorker(value) {
  allowed(value.image === PIN && JSON.stringify(value.command) === JSON.stringify(COMMAND) && value.user === '65532:65532' &&
    value.project === 'dip-public-images' && value.service === 'worker' && value.stand === 'v1' && value.publicProject === 'dip-public-images' &&
    value.memory === 4294967296 && value.swap === value.memory && value.cpus === 1000000000 && value.pids === 128);
  return true;
}
function command(binary, args, timeout = 10000, env) {
  const result = spawnSync(binary, args, { cwd: ROOT, timeout, maxBuffer: 2_000_000, encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'], ...(env ? { env } : {}) });
  // Never relay subprocess stderr, exception details or assertion diffs.
  if (result.status !== 0 || result.error || result.signal) {
      const error = new Error('Bounded command failed');
      error.diagnostics = { moduleResolution: /ERR_MODULE_NOT_FOUND|Cannot find module|Cannot find package/.test(result.stderr ?? ''),
        permission: /EACCES|Permission denied/.test(result.stderr ?? ''), transform: /TransformError|decorators/.test(result.stderr ?? ''),
        timeout: result.error?.code === 'ETIMEDOUT', nonzero: result.status !== 0 };
      throw error;
    }
  return result.stdout;
}
const docker = args => command('docker', args);
function worker() {
  return JSON.parse(docker(['inspect', WORKER, '--format', '{"image":{{json .Image}},"command":{{json .Config.Cmd}},"user":{{json .Config.User}},"project":{{json (index .Config.Labels "com.docker.compose.project")}},"service":{{json (index .Config.Labels "com.docker.compose.service")}},"stand":{{json (index .Config.Labels "org.diplom.public-image-stand")}},"publicProject":{{json (index .Config.Labels "org.diplom.public-image-project")}},"memory":{{.HostConfig.Memory}},"swap":{{.HostConfig.MemorySwap}},"cpus":{{.HostConfig.NanoCpus}},"pids":{{.HostConfig.PidsLimit}}}']));
}
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function sourceHashes() {
  const result = {};
  const walk = path => {
    for (const item of readdirSync(join(ROOT, path), { withFileTypes: true })) {
      const name = `${path}/${item.name}`;
      if (item.isDirectory()) walk(name);
      else if (item.isFile() && /\.(?:ts|tsx|mjs|json)$/.test(name)) result[name] = hash(readFileSync(join(ROOT, name)));
    }
  };
  for (const path of ['server/api/src', 'server/runtime/src', 'src/pages/scans', 'src/shared/api/scans']) walk(path);
  for (const name of readdirSync(join(ROOT, 'scripts')).filter(name => name.startsWith('public-secrets-qualification'))) {
    if (lstatSync(join(ROOT, 'scripts', name)).isFile()) result[`scripts/${name}`] = hash(readFileSync(join(ROOT, 'scripts', name)));
  }
  return result;
}
export function createArgs(name, temp) {
  allowed(/^public-secrets-qualification-[a-f0-9-]{36}$/.test(name));
  allowed(temp.startsWith(join(tmpdir(), 'public-secrets-qualification-')) && !temp.includes(','));
  return ['create', '--name', name, '--pull', 'never', '--network', 'none', '--read-only', '--user', '65532:65532',
    '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--memory', '4g', '--memory-swap', '4g', '--cpus', '1', '--pids-limit', '128',
    '--log-driver', 'none', '--ulimit', 'core=0:0', '--workdir', '/app/server/api', '--entrypoint', 'node',
    '--label', `org.diplom.secrets-qualification=${name}`,
    '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,uid=65532,gid=65532,mode=1777,size=16m',
    '--tmpfs', '/tmp/trivy:rw,noexec,nosuid,nodev,uid=65532,gid=65532,mode=700,size=2304m',
    '--env', 'TSX_DISABLE_CACHE=1', '--env', 'HOME=/tmp',
    '--mount', `type=bind,source=${temp}/api-src,target=/app/server/api/src,readonly`,
    '--mount', `type=bind,source=${temp}/runtime-src,target=/app/server/runtime/src,readonly`,
    ...['native.ts', 'fixture.mjs'].flatMap(suffix => ['--mount',
      `type=bind,source=${ROOT}/scripts/public-secrets-qualification-${suffix},target=/app/scripts/public-secrets-qualification-${suffix},readonly`]),
    '--mount', `type=bind,source=${temp}/output,target=/qualification-output`,
    PIN, '--import', 'tsx', '/app/scripts/public-secrets-qualification-native.ts'];
}
function verifyContainer(name, temp) {
  const data = JSON.parse(docker(['inspect', name, '--format', '{"host":{{json .HostConfig}},"mounts":{{json .Mounts}},"image":{{json .Image}},"entrypoint":{{json .Config.Entrypoint}},"cmd":{{json .Config.Cmd}},"user":{{json .Config.User}}}']));
  const h = data.host;
  allowed(data.image === PIN && data.user === '65532:65532' && JSON.stringify(data.entrypoint) === '["node"]' &&
    JSON.stringify(data.cmd) === JSON.stringify(['--import', 'tsx', '/app/scripts/public-secrets-qualification-native.ts']) &&
    h.NetworkMode === 'none' && h.ReadonlyRootfs && !h.Privileged && h.Memory === 4294967296 && h.MemorySwap === h.Memory &&
    h.NanoCpus === 1000000000 && h.PidsLimit === 128 && h.CapDrop.includes('ALL') && !h.CapAdd?.length &&
    h.SecurityOpt.includes('no-new-privileges:true') && h.LogConfig.Type === 'none' && Object.keys(h.PortBindings ?? {}).length === 0 && !h.Devices?.length);
  allowed(data.mounts.length === 5 && data.mounts.every(m => m.Type === 'bind' && !m.Source.includes('docker.sock') &&
    (m.Destination === '/qualification-output' ? m.RW && m.Source === `${temp}/output` : !m.RW)));
  allowed(h.Tmpfs['/tmp/trivy'].includes('size=2304m') && h.Tmpfs['/tmp/trivy'].includes('nodev') && h.Tmpfs['/tmp'].includes('size=16m'));
  return { networkNone: true, readonlyRoot: true, nonroot: true, capsDropped: true, noNewPrivileges: true, noSocket: true,
    noFixtureEntrypoint: true, loggingDisabled: true, mountCount: 5, memory: h.Memory, memorySwap: h.MemorySwap, cpus: 1, pids: 128 };
}

export function qualificationDestination(args) {
  allowed(args.length === 0 || args.length === 1 && args[0] === '--dedup');
  return join(ROOT, `docs/public-secrets-qualification-20261020${args.length ? '.dedup' : ''}.json`);
}

export async function run() {
  process.umask(0o077);
  const destination = qualificationDestination(process.argv.slice(2));
  allowed(!existsSync(destination));
  const startedAt = new Date().toISOString();
  let stage = 'docker-availability', temp, name;
  let absent = false, evidence;
  try {
    docker(['info', '--format', '{{json .ServerVersion}}']);
    stage = 'public-worker-verification'; const beforeWorker = worker(); validateWorker(beforeWorker);
    allowed(docker(['image', 'inspect', PIN, '--format', '{{.Id}}']).trim() === PIN);
    const before = sourceHashes();
    const historicalArtifacts = Object.fromEntries(readdirSync(join(ROOT, 'docs'))
      .filter(file => file.startsWith('public-secrets-qualification-20261020.'))
      .map(file => [`docs/${file}`, hash(readFileSync(join(ROOT, 'docs', file)))]));
    temp = mkdtempSync(join(tmpdir(), 'public-secrets-qualification-'));
    allowed((lstatSync(temp).mode & 0o777) === 0o700);
    mkdirSync(join(temp, 'output'), { mode: 0o777 }); chmodSync(join(temp, 'output'), 0o777);
    // Private snapshots prevent another agent's concurrent source edits changing the running guard.
    cpSync(join(ROOT, 'server/api/src'), join(temp, 'api-src'), { recursive: true, dereference: false });
    cpSync(join(ROOT, 'server/runtime/src'), join(temp, 'runtime-src'), { recursive: true, dereference: false });
    chmodSync(join(temp, 'api-src'), 0o755); chmodSync(join(temp, 'runtime-src'), 0o755);
    name = `public-secrets-qualification-${randomUUID()}`;
    stage = 'create'; docker(createArgs(name, temp));
    stage = 'isolation'; const isolation = verifyContainer(name, temp);
    stage = 'native-cohort';
    // Attached stdout/stderr captured privately; only explicit safe counters are printed below.
    const attached = command('docker', ['start', '--attach', name], 150000);
    allowed(JSON.parse(attached.trim()).passed === true);
    const state = JSON.parse(docker(['inspect', name, '--format', '{{json .State}}']));
    allowed(state.Status === 'exited' && state.ExitCode === 0 && !state.OOMKilled);
    evidence = JSON.parse(readFileSync(join(temp, 'output/handoff.json'), 'utf8'));
    stage = 'ui';
    const uiFile = join(temp, 'ui.json');
    const cleanEnv = { PATH: process.env.PATH, HOME: tmpdir(), TSX_DISABLE_CACHE: '1', PUBLIC_SECRETS_HANDOFF: join(temp, 'output/handoff.json'), PUBLIC_SECRETS_UI_RESULT: uiFile };
    command(process.execPath, ['node_modules/vitest/vitest.mjs', 'run', '--config', 'scripts/public-secrets-qualification-vitest.config.ts'], 60000, cleanEnv);
    const ui = JSON.parse(readFileSync(uiFile, 'utf8')); allowed(ui.passed === true && ui.tests === 4);
    evidence.ui = ui;
    stage = 'source-and-worker-preservation';
    allowed(JSON.stringify(before) === JSON.stringify(sourceHashes()));
    allowed(JSON.stringify(beforeWorker) === JSON.stringify(worker()));
    allowed(Object.entries(historicalArtifacts).every(([file, digest]) => hash(readFileSync(join(ROOT, file))) === digest));
    evidence.historicalArtifacts = { preserved: true, hashes: historicalArtifacts };
    evidence.sourceHashes = before;
    evidence.worker = { image: PIN, command: COMMAND, labelsVerified: true, observedResourcesUnchanged: true };
    evidence.isolation = isolation;
    evidence.sourceStable = true;
        evidence.passed = true;
        evidence.execution = { startedAt, completedAt: new Date().toISOString(), disposableContainer: name };
  } catch (error) {
    // Failure labels contain no secret-bearing subprocess text. Do not save raw diagnostics.
    let nativeFailure;
    if (temp && existsSync(join(temp, 'output/failure.json'))) nativeFailure = JSON.parse(readFileSync(join(temp, 'output/failure.json'), 'utf8'));
    evidence = { ...evidence, passed: false, stage, ...(error.diagnostics ? { diagnostics: error.diagnostics } : {}), ...(nativeFailure ? { nativeFailure } : {}),
          ...(temp && existsSync(join(temp, 'ui.json')) ? { ui: JSON.parse(readFileSync(join(temp, 'ui.json'), 'utf8')) } : {}) };
  } finally {
    if (name) {
      try {
        // A timed-out create can have succeeded server-side. Inspect only our exact
        // UUID name, and never delete anything whose ownership label differs.
        const existing = docker(['ps', '-a', '--filter', `name=^/${name}$`, '--format', '{{.Names}}']).trim();
        if (existing) {
          allowed(existing === name);
          allowed(docker(['inspect', name, '--format', '{{index .Config.Labels "org.diplom.secrets-qualification"}}']).trim() === name);
          docker(['rm', '--force', name]);
        }
        absent = docker(['ps', '-a', '--filter', `name=^/${name}$`, '--format', '{{.Names}}']).trim() === '';
      } catch { absent = false; }
    } else absent = true;
    if (temp && absent) rmSync(temp, { recursive: true, force: true });
    evidence.cleanup = { containerAbsent: absent, privateTempRemoved: !!temp && !existsSync(temp) };
    if (!absent) {
          evidence.passed = false;
          evidence.cleanup.ownResourceForCoordinator = name;
          evidence.cleanup.retainedPrivateDirectory = temp;
        }
  }
  // wx refuses accidental replacement of a previous packet; coordinator can archive/rename explicitly.
  writeFileSync(destination, JSON.stringify(evidence, null, 2) + '\n', { flag: 'wx', mode: 0o600 });
  const passed = evidence.passed !== false && absent;
  process.stdout.write(JSON.stringify({ passed, checks: Object.keys(evidence.checks ?? {}).length,
    nativeInvocations: evidence.counts?.nativeInvocations ?? 0, uiTests: evidence.ui?.tests ?? 0,
    containerRemoved: absent, privateTempRemoved: evidence.cleanup.privateTempRemoved }) + '\n');
  if (!passed) process.exitCode = 1;
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) run().catch(() => {
  process.stdout.write('{"passed":false}\n'); process.exitCode = 1;
});
