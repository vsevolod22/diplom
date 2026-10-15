// Browser-safe closed contract; no daemon, Node or image-parser dependency.
export const EXCLUSIONS = [
  'writable-layer',
  'volume-contents',
  'traffic',
  'effective-isolation',
  'exploitability',
  'whole-host',
] as const;
export const HEX = /^[a-f0-9]{64}$/;
export const ID = /^[a-f0-9]{32}$/;
export const SLUG = /^[a-z][a-z0-9-]{0,31}$/;
export const DIGEST = /^sha256:[a-f0-9]{64}$/;
export function invalid(): never {
  throw new Error('INVALID_RUNTIME_INPUT');
}
export function object(v: unknown): Record<string, unknown> {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return invalid();
  return v as Record<string, unknown>;
}
export function exact(v: unknown, keys: string[]): Record<string, unknown> {
  const o = object(v);
  if (Object.keys(o).length !== keys.length || keys.some((k) => !Object.hasOwn(o, k))) invalid();
  return o;
}
export function str(v: unknown, pattern: RegExp): string {
  if (typeof v !== 'string' || !pattern.test(v)) return invalid();
  return v;
}
export function integer(v: unknown, min = 0): number {
  if (!Number.isSafeInteger(v) || Number(v) < min) return invalid();
  return v as number;
}
export function one<T extends string>(v: unknown, choices: readonly T[]): T {
  if (typeof v !== 'string' || !choices.includes(v as T)) return invalid();
  return v as T;
}
export function timestamp(v: unknown): string {
  if (
    typeof v !== 'string' ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(v) ||
    !Number.isFinite(Date.parse(v)) ||
    new Date(v).toISOString() !== v
  )
    return invalid();
  return v;
}
export function canonical(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonical).join(',')}]`;
  if (v && typeof v === 'object')
    return `{${Object.keys(v)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonical((v as Record<string, unknown>)[k])}`)
      .join(',')}}`;
  const text = JSON.stringify(v);
  if (text === undefined) return invalid();
  return text;
}
const flag = (v: unknown): boolean => {
  if (typeof v !== 'boolean') return invalid();
  return v;
};
const resource = (v: unknown) => (v === 'unknown' ? v : integer(v));
const caps = new Set(
  'CHOWN DAC_OVERRIDE DAC_READ_SEARCH FOWNER FSETID KILL SETGID SETUID SETPCAP LINUX_IMMUTABLE NET_BIND_SERVICE NET_BROADCAST NET_ADMIN NET_RAW IPC_LOCK IPC_OWNER SYS_MODULE SYS_RAWIO SYS_CHROOT SYS_PTRACE SYS_PACCT SYS_ADMIN SYS_BOOT SYS_NICE SYS_RESOURCE SYS_TIME SYS_TTY_CONFIG MKNOD LEASE AUDIT_WRITE AUDIT_CONTROL SETFCAP MAC_OVERRIDE MAC_ADMIN SYSLOG WAKE_ALARM BLOCK_SUSPEND AUDIT_READ PERFMON BPF CHECKPOINT_RESTORE ALL unknown'.split(
    ' ',
  ),
);
export type Snapshot = {
  schemaVersion: 'inspect-snapshot-v1';
  containerId: string;
  context: { id: string; version: number };
  observedAt: string;
  coverage: 'runtime-config-inspect';
  facts: Record<string, unknown>;
  hash: string;
};
export function snapshot(v: unknown): Snapshot {
  const s = exact(v, ['schemaVersion', 'containerId', 'context', 'observedAt', 'coverage', 'facts', 'hash']);
  one(s.schemaVersion, ['inspect-snapshot-v1']);
  str(s.containerId, HEX);
  str(s.hash, HEX);
  timestamp(s.observedAt);
  one(s.coverage, ['runtime-config-inspect']);
  const context = exact(s.context, ['id', 'version']);
  str(context.id, SLUG);
  integer(context.version, 1);
  const f = exact(s.facts, [
    'configuredUser',
    'privileged',
    'readonlyRootfs',
    'capAdd',
    'capDrop',
    'security',
    'namespaces',
    'mounts',
    'ports',
    'resources',
  ]);
  one(f.configuredUser, ['root', 'non-root', 'unknown']);
  flag(f.privileged);
  flag(f.readonlyRootfs);
  for (const name of ['capAdd', 'capDrop']) {
    const a = f[name];
    if (a === 'unknown') continue;
    if (
      !Array.isArray(a) ||
      a.length > 64 ||
      new Set(a).size !== a.length ||
      a.some((c) => typeof c !== 'string' || !caps.has(c)) ||
      canonical(a) !== canonical([...a].sort())
    )
      invalid();
  }
  const security = exact(f.security, ['seccomp', 'apparmor']);
  for (const mode of Object.values(security)) one(mode, ['unknown', 'default', 'custom', 'unconfined']);
  const namespaces = exact(f.namespaces, ['network', 'pid', 'ipc', 'user']);
  for (const mode of Object.values(namespaces)) one(mode, ['unknown', 'private', 'host', 'shared-container']);
  if (namespaces.user !== 'unknown' && namespaces.user !== 'host') invalid();
  const mounts = exact(f.mounts, ['groups', 'socketPresent']);
  if (mounts.socketPresent !== 'unknown') flag(mounts.socketPresent);
  if (mounts.groups !== 'unknown') {
    if (!Array.isArray(mounts.groups) || mounts.groups.length > 18) invalid();
    const keys = new Set<string>();
    for (const raw of mounts.groups as unknown[]) {
      const g = exact(raw, ['type', 'readOnly', 'count']);
      one(g.type, ['bind', 'volume', 'tmpfs', 'npipe', 'cluster', 'unknown']);
      if (g.readOnly !== 'unknown') flag(g.readOnly);
      integer(g.count, 1);
      if (Number(g.count) > 256) invalid();
      const key = `${g.type}:${g.readOnly}`;
      if (keys.has(key)) invalid();
      keys.add(key);
    }
  }
  if (f.ports !== 'unknown') {
    if (!Array.isArray(f.ports) || f.ports.length > 256) invalid();
    const keys = new Set<string>();
    for (const raw of f.ports as unknown[]) {
      const p = exact(raw, ['port', 'protocol', 'published']);
      integer(p.port, 1);
      if (Number(p.port) > 65535) invalid();
      one(p.protocol, ['tcp', 'udp', 'sctp']);
      flag(p.published);
      const key = `${p.port}/${p.protocol}`;
      if (keys.has(key)) invalid();
      keys.add(key);
    }
  }
  const resources = exact(f.resources, ['memory', 'nanoCpus', 'pids', 'cpuQuota', 'cpuPeriod']);
  Object.values(resources).forEach(resource);
  if (new TextEncoder().encode(canonical(s)).length > 32768) invalid();
  return structuredClone(s) as Snapshot;
}
export type Capture = {
  schemaVersion: 'runtime-capture-v1';
  snapshot: Snapshot;
  startedAt: string;
  endedAt: string;
  running: boolean | 'unknown';
  imageConfigDigest: string | null;
  imageSemantics: 'docker-config-sha256-v1' | 'unknown';
  binding: { nonce: string; consentId: string; authorityEpoch: number };
  hash: string;
};
export function capture(v: unknown): Capture {
  const c = exact(v, [
    'schemaVersion',
    'snapshot',
    'startedAt',
    'endedAt',
    'running',
    'imageConfigDigest',
    'imageSemantics',
    'binding',
    'hash',
  ]);
  one(c.schemaVersion, ['runtime-capture-v1']);
  snapshot(c.snapshot);
  str(c.hash, HEX);
  const binding = exact(c.binding, ['nonce', 'consentId', 'authorityEpoch']);
  str(binding.nonce, HEX);
  str(binding.consentId, ID);
  integer(binding.authorityEpoch, 1);
  const start = timestamp(c.startedAt);
  const end = timestamp(c.endedAt);
  if (
    Date.parse(start) > Date.parse(end) ||
    Date.parse(end) - Date.parse(start) > 5000 ||
    (c.snapshot as Snapshot).observedAt !== end
  )
    invalid();
  if (c.running !== 'unknown') flag(c.running);
  one(c.imageSemantics, ['docker-config-sha256-v1', 'unknown']);
  if (c.imageConfigDigest !== null) str(c.imageConfigDigest, DIGEST);
  if ((c.imageConfigDigest === null) !== (c.imageSemantics === 'unknown')) invalid();
  return structuredClone(c) as Capture;
}
export type Mode = 'imported-historical' | 'broker-capture';
export type Target = {
  targetId: string;
  containerId: string;
  context: string;
  contextVersion: number;
  version: number;
  importAllowed: boolean;
  liveAllowed: boolean;
};
export function target(v: unknown): Target {
  const t = exact(v, [
    'targetId',
    'containerId',
    'context',
    'contextVersion',
    'version',
    'importAllowed',
    'liveAllowed',
  ]);
  str(t.targetId, ID);
  str(t.containerId, HEX);
  str(t.context, SLUG);
  integer(t.contextVersion, 1);
  integer(t.version, 1);
  flag(t.importAllowed);
  flag(t.liveAllowed);
  return t as Target;
}
export type ImportPayload = {
  schema: 'runtime-import-v1';
  subject: string;
  targetId: string;
  targetVersion: number;
  consentId: string;
  nonce: string;
  signerId: string;
  sourceVersion: 'operator-runtime-v1';
  capture: Capture;
};
export function payload(v: unknown): ImportPayload {
  const p = exact(v, [
    'schema',
    'subject',
    'targetId',
    'targetVersion',
    'consentId',
    'nonce',
    'signerId',
    'sourceVersion',
    'capture',
  ]);
  one(p.schema, ['runtime-import-v1']);
  str(p.subject, /^[A-Za-z0-9:_-]{1,128}$/);
  str(p.targetId, ID);
  integer(p.targetVersion, 1);
  str(p.consentId, ID);
  str(p.nonce, HEX);
  str(p.signerId, ID);
  one(p.sourceVersion, ['operator-runtime-v1']);
  capture(p.capture);
  return p as ImportPayload;
}
export const REASONS = [
  'READY',
  'QUALIFICATION_MISSING',
  'TRANSPORT_UNSUPPORTED',
  'INVALID_RUNTIME_INPUT',
  'NOT_AUTHORIZED',
  'RUNTIME_UNAVAILABLE',
  'INDETERMINATE',
  'TARGET_NOT_RUNNING',
  'CANCELLED',
  'IMAGE_LINK_UNAVAILABLE',
  'IMAGE_IDENTITY_MISMATCH',
  'IMAGE_RESULT_UNAVAILABLE',
] as const;
export type Outcome = {
  outcome: 'checked' | 'unsupported' | 'not_authorized' | 'failed' | 'skipped';
  reason: (typeof REASONS)[number];
  scannerVersion: string | null;
  checkedAt: string | null;
  dbEvidenceHash: string | null;
};
export type ImageLink = {
  imageScanId: string;
  manifestDigest: string;
  configDigest: string;
  platform: string;
  verificationVersion: 'image-config-chain-v1';
  captureHash: string;
  linkedAt: string;
  sbom: Outcome;
  vuln: Outcome;
};
export function link(v: unknown): ImageLink {
  const l = exact(v, [
    'imageScanId',
    'manifestDigest',
    'configDigest',
    'platform',
    'verificationVersion',
    'captureHash',
    'linkedAt',
    'sbom',
    'vuln',
  ]);
  str(l.imageScanId, /^[a-f0-9-]{36}$/);
  str(l.manifestDigest, DIGEST);
  str(l.configDigest, DIGEST);
  one(l.platform, ['linux/amd64']);
  one(l.verificationVersion, ['image-config-chain-v1']);
  str(l.captureHash, HEX);
  timestamp(l.linkedAt);
  for (const k of ['sbom', 'vuln']) {
    const o = exact(l[k], ['outcome', 'reason', 'scannerVersion', 'checkedAt', 'dbEvidenceHash']);
    one(o.outcome, ['checked', 'unsupported', 'not_authorized', 'failed', 'skipped']);
    one(o.reason, REASONS);
    if ((o.outcome === 'checked') !== (o.reason === 'READY')) invalid();
    if (o.scannerVersion !== null) str(o.scannerVersion, /^[0-9][a-zA-Z0-9.+-]{0,63}$/);
    if (o.checkedAt !== null) timestamp(o.checkedAt);
    if (o.dbEvidenceHash !== null) str(o.dbEvidenceHash, HEX);
    if (
      (o.outcome === 'checked' && (!o.scannerVersion || !o.checkedAt)) ||
      (o.outcome !== 'checked' &&
        (o.scannerVersion !== null || o.checkedAt !== null || o.dbEvidenceHash !== null))
    )
      invalid();
  }
  return l as ImageLink;
}
export type Report = {
  captureId: string;
  subject: string;
  target: Target;
  mode: Mode;
  state: 'running' | 'completed' | 'failed' | 'cancelled';
  reason: (typeof REASONS)[number];
  createdAt: string;
  receivedAt: string | null;
  consentId: string;
  checksVersion: 'runtime-config-v1';
  resourcePolicyVersion: 'runtime-host-policy-v1';
  evidence: Capture | null;
  provenance: { signerId: string; sourceVersion: 'operator-runtime-v1' } | null;
  links: ImageLink[];
  exclusions: typeof EXCLUSIONS;
};
export function report(v: unknown): Report {
  const r = exact(v, [
    'captureId',
    'subject',
    'target',
    'mode',
    'state',
    'reason',
    'createdAt',
    'receivedAt',
    'consentId',
    'checksVersion',
    'resourcePolicyVersion',
    'evidence',
    'provenance',
    'links',
    'exclusions',
  ]);
  str(r.captureId, ID);
  str(r.subject, /^[A-Za-z0-9:_-]{1,128}$/);
  target(r.target);
  one(r.mode, ['imported-historical', 'broker-capture']);
  one(r.state, ['running', 'completed', 'failed', 'cancelled']);
  one(r.reason, REASONS);
  if (
    r.state === 'running' || r.state === 'completed'
      ? r.reason !== 'READY'
      : r.state === 'cancelled'
        ? r.reason !== 'CANCELLED'
        : r.reason === 'READY' || r.reason === 'CANCELLED'
  )
    invalid();
  timestamp(r.createdAt);
  str(r.consentId, ID);
  one(r.checksVersion, ['runtime-config-v1']);
  one(r.resourcePolicyVersion, ['runtime-host-policy-v1']);
  if (canonical(r.exclusions) !== canonical(EXCLUSIONS)) invalid();
  if (r.receivedAt !== null) timestamp(r.receivedAt);
  if (r.evidence !== null) {
    const c = capture(r.evidence);
    const t = r.target as Target;
    if (
      c.binding.consentId !== r.consentId ||
      c.snapshot.containerId !== t.containerId ||
      c.snapshot.context.id !== t.context ||
      c.snapshot.context.version !== t.contextVersion ||
      r.state !== 'completed' ||
      r.reason !== 'READY' ||
      r.receivedAt === null
    )
      invalid();
    if (r.mode === 'broker-capture' && c.running !== true) invalid();
  } else if (r.state === 'completed' || r.receivedAt !== null || r.provenance !== null) invalid();
  if (r.mode === 'imported-historical' && r.evidence !== null) {
    const p = exact(r.provenance, ['signerId', 'sourceVersion']);
    str(p.signerId, ID);
    one(p.sourceVersion, ['operator-runtime-v1']);
  } else if (r.provenance !== null) invalid();
  if (!Array.isArray(r.links) || r.links.length > 8) invalid();
  const linkIds = new Set<string>();
  for (const raw of r.links as unknown[]) {
    const l = link(raw);
    if (linkIds.has(l.imageScanId)) invalid();
    linkIds.add(l.imageScanId);
    if (
      !r.evidence ||
      l.captureHash !== (r.evidence as Capture).hash ||
      l.configDigest !== (r.evidence as Capture).imageConfigDigest
    )
      invalid();
  }
  return structuredClone(r) as Report;
}
