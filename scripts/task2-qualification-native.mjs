import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export const IMAGE = 'sha256:bcc376de8d77cfe086a917230e818dc9f8528e3c852f7b1aff648949b6258d1c';
export const CONTEXT = 'desktop-linux';
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export function check(condition, label) { if (!condition) throw new Error(label); }
// Never include child stdout/stderr or assertion values in an exception.
export function docker(args, timeout = 10000, maxBuffer = 8_000_000) {
  return spawnSync('docker', ['--context', CONTEXT, ...args], {
    timeout, maxBuffer, encoding: 'utf8', env: { PATH: process.env.PATH, HOME: process.env.HOME },
  });
}
export function publicField(args) {
  const result = docker(args);
  check(result.status === 0 && !result.error, 'public-field-query-failed');
  return result.stdout.trim();
}

// Small deterministic regular-file-only Docker archive; never extracted on the host.
export function tar(files) {
  const chunks = [];
  for (const [name, input] of Object.entries(files)) {
    check(/^[a-zA-Z0-9][a-zA-Z0-9/._-]{0,98}$/.test(name) && !name.split('/').includes('..'), 'fixture-path');
    const body = Buffer.isBuffer(input) ? input : Buffer.from(input);
    check(body.length < 1_000_000, 'fixture-size');
    const header = Buffer.alloc(512);
    header.write(name); header.write('0000644\0', 100); header.write('0000000\0', 108); header.write('0000000\0', 116);
    header.write(body.length.toString(8).padStart(11, '0') + '\0', 124); header.write('00000000000\0', 136);
    header.fill(32, 148, 156); header[156] = 48; header.write('ustar\0', 257); header.write('00', 263);
    header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
    chunks.push(header, body, Buffer.alloc((512 - body.length % 512) % 512));
  }
  return Buffer.concat([...chunks, Buffer.alloc(1024)]);
}
export function fixture(osVersion = '3.22.2') {
  const secrets = [0, 1].map(() => 'ghp_' + randomBytes(18).toString('hex'));
  const marker = 'TASK2_TRANSIENT_PATH_' + randomBytes(8).toString('hex');
  const layer = tar({
    'etc/alpine-release': osVersion + '\n',
    'etc/os-release': `NAME="Alpine Linux"\nID=alpine\nVERSION_ID=${osVersion}\n`,
    'lib/apk/db/installed': 'P:busybox\nV:1.37.0-r12\nA:x86_64\nS:1000\nI:1000\nT:fixture inventory\no:busybox\nL:GPL-2.0-only\n\n',
    'app/node_modules/lodash/package.json': JSON.stringify({ name: 'lodash', version: '4.17.20', license: 'MIT' }),
    [`app/${marker}.txt`]: secrets.map((secret, i) => `github_token_${i} = "${secret}"`).join('\n') + '\n',
  });
  const diffId = 'sha256:' + sha256(layer);
  const config = Buffer.from(JSON.stringify({ architecture: 'amd64', os: 'linux',
    rootfs: { type: 'layers', diff_ids: [diffId] }, config: {}, history: [{ created: '2026-10-16T00:00:00Z' }] }));
  const configHash = sha256(config);
  const archive = tar({ [configHash + '.json']: config, 'layer/layer.tar': layer,
    'manifest.json': JSON.stringify([{ Config: configHash + '.json', RepoTags: ['task2-inventory:local'], Layers: ['layer/layer.tar'] }]) });
  return { archive, secrets, marker, diffId, configDigest: 'sha256:' + configHash, archiveSha256: sha256(archive), osVersion };
}
export function createArgs(name, directory, dbDirectory, scannerArgs) {
  check(/^task2-qualification-[a-f0-9-]+$/.test(name), 'container-name');
  return ['create', '--name', name, '--label', 'dip.task2.qualification=true', '--pull', 'never',
    '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true', '--network', 'none',
    '--user', '65532:65532', '--pids-limit', '64', '--memory', '1g', '--memory-swap', '1g', '--cpus', '1',
    '--log-driver', 'none', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777',
        '--tmpfs', '/tmp/cache:rw,noexec,nosuid,nodev,size=512m,uid=65532,gid=65532',
    '--mount', `type=bind,src=${directory},dst=/fixture,readonly`,
    ...(dbDirectory ? ['--mount', `type=bind,src=${dbDirectory},dst=/tmp/cache/db,readonly`] : []),
    '--entrypoint', '/usr/local/bin/trivy', IMAGE, ...scannerArgs];
}
export function nativeScan(f, scanner, dbDirectory, records) {
  const directory = mkdtempSync(join(tmpdir(), 'task2-qualification-'));
  const name = 'task2-qualification-' + randomUUID();
  const record = { name, scanner, cleanup: false };
  records.push(record);
  writeFileSync(join(directory, 'image.tar'), f.archive, { mode: 0o644 });
  let created = false;
  try {
    const args = scanner === 'version' ? ['--version'] : ['image', '--input', '/fixture/image.tar', '--scanners', scanner, '--format', 'json',
      '--quiet', '--offline-scan', '--skip-db-update', '--skip-java-db-update', '--list-all-pkgs',
      '--cache-dir', '/tmp/cache', '--timeout', '60s'];
    const result = docker(createArgs(name, directory, dbDirectory, args));
    created = result.status === 0 && !result.error;
    check(created, 'container-create-failed');
    const guard = JSON.parse(publicField(['inspect', '--format',
      '{"image":{{json .Image}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"network":{{json .HostConfig.NetworkMode}},"privileged":{{json .HostConfig.Privileged}},"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"user":{{json .Config.User}},"mounts":{{json .Mounts}}}', name]));
    check(guard.image === IMAGE && guard.readonly && guard.network === 'none' && !guard.privileged &&
      guard.caps.includes('ALL') && guard.security.includes('no-new-privileges:true') && guard.user === '65532:65532' &&
      guard.mounts.filter(m => m.Type === 'bind').every(m => !m.RW) &&
      guard.mounts.filter(m => m.Type === 'bind').length === (dbDirectory ? 2 : 1), 'container-isolation');
    record.isolation = { image: guard.image, readonly: true, network: 'none', privileged: false, capDrop: ['ALL'], noNewPrivileges: true, user: guard.user, readOnlyBinds: dbDirectory ? 2 : 1 };
    const run = docker(['start', '--attach', name], 75000);
    check(!run.error && run.signal === null, 'scanner-deadline-or-output-bound');
    const exitCode = Number(publicField(['inspect', '--format', '{{.State.ExitCode}}', name]));
    record.exitCode = exitCode;
    record.stdoutBytes = Buffer.byteLength(run.stdout);
    record.stderrBytes = Buffer.byteLength(run.stderr);
        record.diagnosticClasses = ['permission denied', 'read-only file system', 'database error', 'unable to open', 'first run', 'skip-db-update', 'no such file'].filter(s => run.stderr.toLowerCase().includes(s));
    record.stdoutSha256 = sha256(run.stdout);
    // Reports remain in process memory only. Docker logging is disabled.
    if (scanner === 'version') {
          check(exitCode === 0 && /^Version: 0\.69\.3\s*$/.test(run.stdout.trim()), 'native-version-mismatch');
          record.version = '0.69.3';
        }
        const report = exitCode === 0 && scanner !== 'version' ? JSON.parse(run.stdout) : null;
    if (report) {
      check(report.SchemaVersion === 2 && report.ArtifactType === 'container_image' &&
        report.ArtifactName === '/fixture/image.tar' && report.Metadata.ImageID === f.configDigest &&
        JSON.stringify(report.Metadata.DiffIDs) === JSON.stringify([f.diffId]) &&
        report.Metadata.ImageConfig.architecture === 'amd64', 'native-fixture-identity');
    }
    return { report, exitCode, record };
  } finally {
    // Even a timed-out create may have created a container. Query only our UUID name.
    const removed = docker(['rm', '--force', name]);
    const remaining = docker(['ps', '--all', '--filter', `name=^/${name}$`, '--format', '{{.ID}}']);
    record.cleanup = !remaining.error && remaining.status === 0 && remaining.stdout.trim() === '' && (!created || removed.status === 0);
    if (record.cleanup) {
      rmSync(directory, { recursive: true });
      record.fixtureRemoved = !existsSync(directory);
    } else {
      record.retainedFixture = directory;
      throw new Error('cleanup-uncertain-owned-fixture-retained');
    }
  }
}
