// Prospective recovery evidence only. No engine calls, secret hashing or authority adoption.
import * as fs from 'node:fs';
import { createHash } from 'node:crypto';
import { isDeepStrictEqual as equal } from 'node:util';
import { dirname } from 'node:path';
import { writeExclusive, syncDirectory } from './setup-local-cve.mjs';

const need = ok => { if (!ok) throw Error('DEPLOY_AUTHORITY_INVALID'); };
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const neutral = v => v === null || v === false || v === 0 || v === '' || Array.isArray(v) && v.length === 0 ||
  v && Object.getPrototypeOf(v) === Object.prototype && Object.keys(v).length === 0;
const CONFIG = new Set(['Hostname','Domainname','User','AttachStdin','AttachStdout','AttachStderr','ExposedPorts','Tty','OpenStdin','StdinOnce',
  'Cmd','Healthcheck','ArgsEscaped','Image','Volumes','WorkingDir','Entrypoint','OnBuild','Labels','StopSignal','StopTimeout','Shell','NetworkDisabled','MacAddress']);
const HOST = new Set(['Memory','MemorySwap','NanoCpus','PidsLimit','MemoryReservation','CpuShares','CpuPeriod','CpuQuota','CpuRealtimePeriod','CpuRealtimeRuntime',
  'CpusetCpus','CpusetMems','OomScoreAdj','ShmSize','IpcMode','PidMode','UTSMode','UsernsMode','CgroupParent','CgroupnsMode','Runtime',
  'Privileged','AutoRemove','ReadonlyRootfs','CapDrop','CapAdd','SecurityOpt','NetworkMode','PortBindings','PublishAllPorts','Tmpfs','MaskedPaths',
  'ReadonlyPaths','MemorySwappiness','OomKillDisable','RestartPolicy','ConsoleSize','LogConfig','Mounts','Ulimits']);
function controls(object, allowed, omit = null) {
  need(object && Object.getPrototypeOf(object) === Object.prototype);
  const result = {};
  for (const key of Object.keys(object).sort()) {
    if (key === omit) continue;
    need(allowed.has(key) || neutral(object[key]));
    result[key] = structuredClone(object[key]);
  }
  return result;
}
// Call the existing complete container/image validators BEFORE this projection.
// Docker Config.Env is immutable for an unchanged full container ID + Created;
// recovery revalidates Env against the immutable image/spec and unchanged JWT file.
// No Env bytes (or digest of them) enter this record. Every HostConfig field and
// mount is retained; unknown non-neutral authority fails, neutral additions drift.
export function deploymentAuthority(observed) {
  return {
    containers: observed.containers.map(c => {
      need(/^[a-f0-9]{64}$/.test(c.Id) && /^sha256:[a-f0-9]{64}$/.test(c.Image) && Number.isFinite(Date.parse(c.Created)));
      return { role: c.Config.Labels['com.docker.compose.service'], Id: c.Id, Image: c.Image, Created: c.Created,
        Name: c.Name, Path: c.Path, Args: c.Args, Config: controls(c.Config, CONFIG, 'Env'), HostConfig: controls(c.HostConfig, HOST),
        Mounts: [...c.Mounts].sort((a,b) => a.Destination.localeCompare(b.Destination)),
        AppArmorProfile: c.AppArmorProfile ?? '', ProcessLabel: c.ProcessLabel ?? '', MountLabel: c.MountLabel ?? '',
        process: [c.State.StartedAt,c.State.FinishedAt,c.State.Running,c.State.Status,c.State.Pid,c.RestartCount,c.State.ExitCode],
        NetworkSettings: c.NetworkSettings };
    }).sort((a,b) => a.role.localeCompare(b.role)),
    networks: [...observed.networks].sort((a,b) => a.Name.localeCompare(b.Name)),
    volumes: [...observed.volumes].sort((a,b) => a.Name.localeCompare(b.Name)),
  };
}
export function deploymentFileIdentity(path, { secret = false } = {}) {
  const a = fs.lstatSync(path);
  need(a.isFile() && !a.isSymbolicLink() && a.nlink === 1 && a.uid === process.getuid() && (a.mode & 0o7777) === 0o600 && a.size <= 262144);
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const stamp = s => [s.dev,s.ino,s.uid,s.mode,s.nlink,s.size,s.mtimeMs,s.ctimeMs];
    need(equal(stamp(a),stamp(fs.fstatSync(fd))));
    // Secret identity is metadata ONLY; its bytes are checked in memory by the caller.
    const value = { stamp: stamp(a), ...(secret ? {} : { sha256: hash(fs.readFileSync(fd)) }) };
    need(equal(stamp(a),stamp(fs.fstatSync(fd))) && equal(stamp(a),stamp(fs.lstatSync(path))));
    return value;
  } finally { fs.closeSync(fd); }
}
const LIMIT = 4 * 1024 ** 2;
export function readEngineJournal(path) {
  const s = fs.lstatSync(path);
  need(s.isFile() && !s.isSymbolicLink() && s.uid === process.getuid() && s.nlink === 1 && (s.mode & 0o7777) === 0o600 && s.size <= LIMIT);
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  let bytes;
  try {
    const opened = fs.fstatSync(fd);
    need(opened.dev === s.dev && opened.ino === s.ino && opened.size === s.size);
    bytes = fs.readFileSync(fd);
  } finally { fs.closeSync(fd); }
  const after = fs.lstatSync(path); need(equal([s.dev,s.ino,s.size,s.mtimeMs,s.ctimeMs],[after.dev,after.ino,after.size,after.mtimeMs,after.ctimeMs]));
  const text = bytes.toString('utf8'); need(Buffer.from(text).equals(bytes) && (text === '' || text.endsWith('\n')));
  const lines = text === '' ? [] : text.slice(0,-1).split('\n');
  const rows = lines.map(line => JSON.parse(line)), ends = [], codes = []; let end = 0;
  need(rows.length <= 20000 && rows.length % 2 === 0);
  for (let i=0;i<rows.length;i+=2) {
    const a = rows[i], b = rows[i+1];
    need(equal(Object.keys(a).sort(),['code','seq','state']) && a.seq === i/2 + 1 && a.state === 'submitted' && /^[A-Z][A-Z0-9_]{1,79}$/.test(a.code));
    need(equal(b,{seq:a.seq,state:'settled',exit:0}));
    end += Buffer.byteLength(lines[i]) + Buffer.byteLength(lines[i+1]) + 2;
    ends.push(end); codes.push(a.code);
  }
  return { bytes, sha256: hash(bytes), count: rows.length / 2, ends, codes };
}
export function createEngineJournal(path, guard) {
  writeExclusive(path, '', 0o600); syncDirectory(dirname(path));
  const fd = fs.openSync(path, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW);
  const original = fs.fstatSync(fd); fs.closeSync(fd);
  let expected = Buffer.alloc(0), seq = 0, pending = false;
  const verify = () => {
    guard(); const s = fs.lstatSync(path);
    need(s.dev === original.dev && s.ino === original.ino && s.nlink === 1 && s.uid === original.uid && s.mode === original.mode && s.size === expected.length);
    const f = fs.openSync(path,fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
    try { need(fs.fstatSync(f).ino === original.ino && fs.readFileSync(f).equals(expected)); } finally { fs.closeSync(f); }
  };
  const append = row => {
    verify(); const bytes = Buffer.from(JSON.stringify(row)+'\n'); need(expected.length + bytes.length <= LIMIT);
    const f = fs.openSync(path,fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_NOFOLLOW);
    try {
      need(fs.fstatSync(f).ino === original.ino);
      let n=0; while(n<bytes.length) n+=fs.writeSync(f,bytes,n,bytes.length-n);
      fs.fsyncSync(f);
    } finally { fs.closeSync(f); }
    expected = Buffer.concat([expected,bytes]); verify();
  };
  return { verify, submit(code) {
    need(!pending && /^[A-Z][A-Z0-9_]{1,79}$/.test(code)); append({seq:++seq,state:'submitted',code}); pending=true;
  }, settle() {
    need(pending); append({seq,state:'settled',exit:0}); pending=false;
  }, checkpoint() {
    verify(); need(!pending); return { bytes:expected.length,sha256:hash(expected),count:seq };
  } };
}
