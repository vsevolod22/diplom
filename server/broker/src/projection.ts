import { createHash } from 'node:crypto';
import { SafeFailure, LIMITS, type Limits } from './contracts.js';
import type { Pin } from './policy.js';
const unknown = 'unknown' as const;
const fail = (): never => {
  throw new SafeFailure('upstream');
};
const object = (v: unknown): Record<string, unknown> => {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return fail();
  return v as Record<string, unknown>;
};
const optionalString = (o: Record<string, unknown>, key: string): string | undefined => {
  if (!(key in o)) return;
  if (typeof o[key] !== 'string') return fail();
  return o[key] as string;
};
const bool = (v: unknown) => (typeof v === 'boolean' ? v : fail());
const capabilities = new Set(
  'CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP LINUX_IMMUTABLE NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE ALL'.split(
    ' ',
  ),
);
function cap(v: unknown): string[] | typeof unknown {
  if (v === undefined || v === null) return unknown;
  if (!Array.isArray(v) || v.length > 64) return fail();
  return [
    ...new Set(
      v.map((item) => {
        if (typeof item !== 'string') return fail();
        const name = item.toUpperCase().replace(/^CAP_/, '');
        return capabilities.has(name) ? name : unknown;
      }),
    ),
  ].sort();
}
function namespace(v: string | undefined): string {
  if (v === undefined) return unknown;
  if (v === 'host') return 'host';
  if (['', 'private', 'default', 'none', 'bridge'].includes(v)) return 'private';
  if (v.startsWith('container:') && v.length > 10) return 'shared-container';
  return unknown;
}
function security(v: unknown): { seccomp: string; apparmor: string } {
  if (v === undefined || v === null) return { seccomp: unknown, apparmor: unknown };
  if (!Array.isArray(v) || v.length > 64 || v.some((x) => typeof x !== 'string')) return fail();
  const classify = (name: string) => {
    const matches = (v as string[]).filter((x) => x.startsWith(`${name}=`) || x.startsWith(`${name}:`));
    if (!matches.length) return 'default';
    if (matches.length !== 1) return unknown;
    const profile = matches[0].slice(name.length + 1);
    return profile === 'unconfined'
      ? 'unconfined'
      : profile === 'default'
        ? 'default'
        : profile
          ? 'custom'
          : unknown;
  };
  return { seccomp: classify('seccomp'), apparmor: classify('apparmor') };
}
function mounts(v: unknown) {
  if (v === undefined) return { groups: unknown, socketPresent: unknown };
  if (!Array.isArray(v) || v.length > 256) return fail();
  const counts = new Map<string, { type: string; readOnly: boolean | typeof unknown; count: number }>();
  let socketPresent: boolean | typeof unknown = v.length ? unknown : false;
  for (const item of v) {
    const m = object(item);
    const type = optionalString(m, 'Type');
    const classification =
      type && ['bind', 'volume', 'tmpfs', 'npipe', 'cluster'].includes(type) ? type : unknown;
    const readOnly = m.RW === undefined ? unknown : !bool(m.RW);
    const source = optionalString(m, 'Source');
    const destination = optionalString(m, 'Destination');
    if ([source, destination].some((s) => s && /(?:^|\/)docker\.sock$/.test(s))) socketPresent = true;
    const key = `${classification}:${readOnly}`;
    const count = counts.get(key) ?? { type: classification, readOnly, count: 0 };
    count.count++;
    counts.set(key, count);
  }
  return {
    groups: [...counts.entries()].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)).map(([, v]) => v),
    socketPresent,
  };
}
function ports(v: unknown) {
  if (v === undefined || v === null) return unknown;
  const bindings = object(v);
  if (Object.keys(bindings).length > 256) return fail();
  return Object.entries(bindings)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
    .map(([key, value]) => {
      const match = /^([1-9][0-9]{0,4})\/(tcp|udp|sctp)$/.exec(key);
      if (!match || Number(match[1]) > 65535) return fail();
      if (value !== null && (!Array.isArray(value) || value.length > 256)) return fail();
      for (const binding of value ?? []) {
        const b = object(binding);
        const port = optionalString(b, 'HostPort');
        optionalString(b, 'HostIp');
        if (port === undefined || !/^(?:0|[1-9][0-9]{0,4})$/.test(port) || Number(port) > 65535)
          return fail();
      }
      return {
        port: Number(match[1]),
        protocol: match[2],
        published: Array.isArray(value) && value.length > 0,
      };
    });
}
function resource(v: unknown): number | typeof unknown {
  if (v === undefined || v === null) return unknown;
  if (!Number.isSafeInteger(v) || Number(v) < 0) return fail();
  return v as number;
}
export function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object')
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical((value as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  return JSON.stringify(value);
}
export function project(raw: unknown, pin: Pin, observedAt: number, bound: Limits = LIMITS) {
  const top = object(raw);
  if (top.Id !== pin.id) return fail();
  const config = object(top.Config);
  const host = object(top.HostConfig);
  const user = optionalString(config, 'User');
  let configuredUser: string = unknown;
  if (user === '' || /^(?:root|0+)(?::[^:]*)?$/.test(user ?? '')) configuredUser = 'root';
  else if (/^[0-9]+(?::[^:]*)?$/.test(user ?? '') && Number.isSafeInteger(Number(user!.split(':')[0])))
    configuredUser = 'non-root';
  const envelope = {
    schemaVersion: 'inspect-snapshot-v1',
    containerId: pin.id,
    context: { id: pin.context.id, version: pin.context.version },
    observedAt: new Date(observedAt).toISOString(),
    coverage: 'runtime-config-inspect',
    facts: {
      configuredUser,
      privileged: bool(host.Privileged),
      readonlyRootfs: bool(host.ReadonlyRootfs),
      capAdd: cap(host.CapAdd),
      capDrop: cap(host.CapDrop),
      security: security(host.SecurityOpt),
      namespaces: {
        network: namespace(optionalString(host, 'NetworkMode')),
        pid: namespace(optionalString(host, 'PidMode')),
        ipc: namespace(optionalString(host, 'IpcMode')),
        user: namespace(optionalString(host, 'UsernsMode')),
      },
      mounts: mounts(top.Mounts),
      ports: ports(host.PortBindings),
      resources: {
        memory: resource(host.Memory),
        nanoCpus: resource(host.NanoCpus),
        pids: resource(host.PidsLimit),
        cpuQuota: resource(host.CpuQuota),
        cpuPeriod: resource(host.CpuPeriod),
      },
    },
  };
  const hash = createHash('sha256').update(canonical(envelope)).digest('hex');
  const snapshot = { ...envelope, hash };
  if (Buffer.byteLength(canonical(snapshot)) > bound.outputBytes) return fail();
  return snapshot;
}
