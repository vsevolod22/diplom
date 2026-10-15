import { createHash } from 'node:crypto';

export const PLAN_ID = 'native-macos-public-facts-v1';
export const SOURCE_VERSION = 'operator-macos-public-facts-v1';
export const MAX_BYTES = 8192;
export const FACT_NAMES = Object.freeze([
  'productVersion',
  'kernelRelease',
  'architecture',
  'physicalMemoryBytes',
  'logicalCpuCount',
]);
export const EXCLUSIONS = Object.freeze([
  'docker-engine',
  'docker-desktop-vm',
  'linux-host',
  'whole-host',
  'security-posture',
  'os-cve',
  'packages',
  'filesystem',
  'processes',
  'network',
  'environment',
  'dockerfile-iac',
  'image-signature',
]);
export const fail = () => {
  throw new Error('INVALID_HOST_EVIDENCE');
};
export function exact(value, keys) {
  if (
    !value ||
    typeof value !== 'object' ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== keys.length ||
    keys.some((key) => !Object.hasOwn(value, key))
  )
    fail();
  return value;
}
export function id(value) {
  if (typeof value !== 'string' || value.length !== 32 || !/^[a-f0-9]{32}$/.test(value)) fail();
  return value;
}
export function timestamp(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value)) fail();
  const n = Date.parse(value);
  if (!Number.isFinite(n) || new Date(n).toISOString() !== value) fail();
  return n;
}
export function binding(value) {
  exact(value, ['subject', 'targetId', 'targetVersion', 'consentId', 'nonce']);
  for (const key of ['subject', 'targetId', 'consentId', 'nonce']) id(value[key]);
  if (!Number.isSafeInteger(value.targetVersion) || value.targetVersion < 1) fail();
  return value;
}
export function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value !== null && typeof value === 'object')
    return `{${Object.keys(value)
      .sort()
      .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
      .join(',')}}`;
  return JSON.stringify(value);
}
export function digest(value) {
  return createHash('sha256')
    .update(`host-evidence-v1\n${canonical(value)}`)
    .digest('hex');
}
export function validFact(name, value) {
  if (!FACT_NAMES.includes(name)) return false;
  if (name === 'architecture') return value === 'arm64' || value === 'x86_64';
  if (name === 'productVersion' || name === 'kernelRelease') {
    return typeof value === 'string' && !/\s/.test(value) && /^[0-9]{1,3}(?:\.[0-9]{1,3}){1,2}$/.test(value);
  }
  return Number.isSafeInteger(value) && value > 0 && value <= (name === 'logicalCpuCount' ? 4096 : 2 ** 50);
}
export function payload(value) {
  exact(value, ['schema', 'sourceVersion', 'platform', 'scope', 'binding', 'startedAt', 'endedAt', 'facts']);
  if (
    value.schema !== 'host-evidence-v1' ||
    value.sourceVersion !== SOURCE_VERSION ||
    value.platform !== 'native-macos' ||
    value.scope !== PLAN_ID
  )
    fail();
  binding(value.binding);
  const start = timestamp(value.startedAt),
    end = timestamp(value.endedAt);
  if (end < start || end - start > 5000) fail();
  exact(value.facts, FACT_NAMES);
  for (const name of FACT_NAMES) {
    const fact = value.facts[name];
    if (fact?.status === 'observed') {
      exact(fact, ['status', 'value']);
      if (!validFact(name, fact.value)) fail();
    } else {
      exact(fact, ['status', 'reason']);
      if (
        fact.status !== 'unavailable' ||
        !['timeout', 'command_failed', 'output_limit', 'invalid_output'].includes(fact.reason)
      )
        fail();
    }
  }
  return value;
}
// Separate host consent is operator-local input, never derived from runtime/image consent.
// reviewed=true records a caller assertion, NOT an independent qualification certificate.
export function authorization(value, now) {
  exact(value, ['binding', 'confirmed', 'reviewed', 'planId', 'issuedAt', 'expiresAt']);
  binding(value.binding);
  const issued = timestamp(value.issuedAt),
    expires = timestamp(value.expiresAt);
  if (
    value.confirmed !== true ||
    value.reviewed !== true ||
    value.planId !== PLAN_ID ||
    !Number.isSafeInteger(now) ||
    issued > now ||
    expires <= now ||
    expires <= issued ||
    expires - issued > 300000
  )
    fail();
  return value;
}
// A canonical-only wire contract prevents duplicate keys/numeric lexical normalization.
// Validate closed shallow schemas BEFORE canonicalizing untrusted JSON (no recursive deep input).
export function parseEnvelope(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength > MAX_BYTES) fail();
  let text, envelope;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
    envelope = JSON.parse(text);
  } catch {
    return fail();
  }
  exact(envelope, ['payload', 'hash', 'signerId', 'signature']);
  payload(envelope.payload);
  id(envelope.signerId);
  if (
    typeof envelope.hash !== 'string' ||
    envelope.hash.length !== 64 ||
    !/^[a-f0-9]{64}$/.test(envelope.hash) ||
    typeof envelope.signature !== 'string' ||
    !/^[A-Za-z0-9_-]{86}$/.test(envelope.signature) ||
    Buffer.from(envelope.signature, 'base64url').toString('base64url') !== envelope.signature ||
    canonical(envelope) !== text
  )
    fail();
  return envelope;
}
