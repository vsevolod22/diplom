import { createHash, createPublicKey, sign, verify } from 'node:crypto';
import {
  EXCLUSIONS,
  MAX_BYTES,
  SOURCE_VERSION,
  authorization,
  binding,
  canonical,
  digest,
  exact,
  fail,
  id,
  parseEnvelope,
  payload,
  timestamp,
} from './contract.mjs';

export function publicFingerprint(key) {
  return createHash('sha256')
    .update(key.export({ type: 'spki', format: 'der' }))
    .digest('hex');
}
export function createSignedEnvelope(input, signerId, privateKey) {
  const evidence = structuredClone(payload(input));
  id(signerId);
  if (privateKey?.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') fail();
  const envelope = {
    payload: evidence,
    hash: digest(evidence),
    signerId,
    signature: sign(null, Buffer.from(`host-evidence-v1\n${canonical(evidence)}`), privateKey).toString(
      'base64url',
    ),
  };
  const bytes = Buffer.from(canonical(envelope));
  if (bytes.length > MAX_BYTES) fail();
  return bytes;
}

// One independently supplied PUBLIC enrollment, NOT an envelope-supplied key or runtime trust.
// No private-key reader, enrollment API, durable store or auto-initialization exists in this PoC.
export class HostIntake {
  #trust;
  #key;
  #consumed = new Set();
  constructor(enrollment) {
    exact(enrollment, [
      'subject',
      'targetId',
      'targetVersion',
      'signerId',
      'sourceVersion',
      'publicKeyDer',
      'fingerprint',
    ]);
    binding({
      subject: enrollment.subject,
      targetId: enrollment.targetId,
      targetVersion: enrollment.targetVersion,
      consentId: '0'.repeat(32),
      nonce: '0'.repeat(32),
    });
    id(enrollment.signerId);
    if (
      enrollment.sourceVersion !== SOURCE_VERSION ||
      typeof enrollment.publicKeyDer !== 'string' ||
      enrollment.publicKeyDer.length > 128 ||
      typeof enrollment.fingerprint !== 'string' ||
      !/^[a-f0-9]{64}$/.test(enrollment.fingerprint)
    )
      fail();
    const bytes = Buffer.from(enrollment.publicKeyDer, 'base64');
    if (bytes.toString('base64') !== enrollment.publicKeyDer) fail();
    try {
      this.#key = createPublicKey({ key: bytes, type: 'spki', format: 'der' });
    } catch {
      return fail();
    }
    if (
      this.#key.asymmetricKeyType !== 'ed25519' ||
      publicFingerprint(this.#key) !== enrollment.fingerprint ||
      !this.#key.export({ type: 'spki', format: 'der' }).equals(bytes)
    )
      fail();
    this.#trust = structuredClone(enrollment);
  }
  accept(bytes, consent, now = Date.now()) {
    if (consent?.confirmed !== true) return { host: 'not_authorized', engineQueried: false };
    let auth;
    try {
      auth = authorization(consent, now);
    } catch {
      return { host: 'not_authorized', engineQueried: false };
    }
    const envelope = parseEnvelope(bytes),
      evidence = envelope.payload;
    const enrolled = this.#trust;
    if (
      canonical(evidence.binding) !== canonical(auth.binding) ||
      evidence.binding.subject !== enrolled.subject ||
      evidence.binding.targetId !== enrolled.targetId ||
      evidence.binding.targetVersion !== enrolled.targetVersion ||
      envelope.signerId !== enrolled.signerId ||
      envelope.hash !== digest(evidence) ||
      !verify(
        null,
        Buffer.from(`host-evidence-v1\n${canonical(evidence)}`),
        this.#key,
        Buffer.from(envelope.signature, 'base64url'),
      )
    )
      fail();
    const start = timestamp(evidence.startedAt),
      end = timestamp(evidence.endedAt);
    if (
      start < timestamp(auth.issuedAt) ||
      end >= timestamp(auth.expiresAt) ||
      end > now + 30000 ||
      now - end > 300000
    )
      fail();
    // Bounded process-local one-use nonce/consent guard only. No crash/restart/replay durability claimed.
    // Both identifiers are consumed, so changing one cannot reuse the other authority.
    const keys = [`nonce:${auth.binding.nonce}`, `consent:${auth.binding.consentId}`];
    if (keys.some((key) => this.#consumed.has(key)) || this.#consumed.size >= 256) fail();
    const artifact = {
      schema: 'host-intake-artifact-v1',
      host: 'historical_import',
      verification: 'enrolled_ed25519_signature',
      liveQualified: false,
      engineQueried: false,
      signerId: enrolled.signerId,
      fingerprint: enrolled.fingerprint,
      evidenceHash: envelope.hash,
      receivedAt: new Date(now).toISOString(),
      evidence,
      exclusions: [...EXCLUSIONS],
    };
    if (Buffer.byteLength(canonical(artifact)) > MAX_BYTES) fail();
    for (const key of keys) this.#consumed.add(key);
    return structuredClone(artifact);
  }
}
