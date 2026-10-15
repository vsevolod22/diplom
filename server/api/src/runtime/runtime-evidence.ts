import { createHash, createPublicKey, verify } from 'node:crypto';
import {
  canonical,
  capture,
  exact,
  HEX,
  payload,
  str,
  type Capture,
  type ImportPayload,
} from '../../../runtime/src/contract.js';
import { fault, type Authority, type Enrollment } from './runtime-store.js';

export const digest = (value: unknown, domain: string) =>
  createHash('sha256')
    .update(`${domain}\n${canonical(value)}`)
    .digest('hex');
export function validateCaptureHash(input: unknown): Capture {
  const c = capture(input);
  const { hash: snapshotHash, ...snapshotBody } = c.snapshot;
  if (createHash('sha256').update(canonical(snapshotBody)).digest('hex') !== snapshotHash)
    fault('INVALID_RUNTIME_INPUT');
  const { hash, ...body } = c;
  if (digest(body, 'runtime-capture-v1') !== hash) fault('INVALID_RUNTIME_INPUT');
  return c;
}
export function verifyImport(
  input: unknown,
  enrollment: Enrollment,
  authority: Authority,
  now: number,
): { payload: ImportPayload; fingerprint: string } {
  const envelope = exact(input, ['payload', 'hash', 'signature']);
  const p = payload(envelope.payload);
  const c = validateCaptureHash(p.capture);
  str(envelope.hash, HEX);
  str(envelope.signature, /^[A-Za-z0-9_-]{86}$/);
  if (
    p.subject !== authority.subject ||
    p.targetId !== authority.target.targetId ||
    p.targetVersion !== authority.target.version ||
    p.consentId !== authority.consentId ||
    p.nonce !== authority.nonce ||
    p.signerId !== enrollment.signerId ||
    p.sourceVersion !== enrollment.sourceVersion ||
    c.snapshot.containerId !== authority.target.containerId ||
    c.snapshot.context.id !== authority.target.context ||
    c.snapshot.context.version !== authority.target.contextVersion
  )
    fault('NOT_AUTHORIZED', 403);
  if (
    c.binding.nonce !== authority.nonce ||
    c.binding.consentId !== authority.consentId ||
    c.binding.authorityEpoch !== authority.epoch
  )
    fault('NOT_AUTHORIZED', 403);
  const age = now - Date.parse(c.endedAt);
  if (age > 300000 || age < -30000) fault('INVALID_RUNTIME_INPUT');
  if (digest(p, 'runtime-import-v1') !== envelope.hash) fault('INVALID_RUNTIME_INPUT');
  const signature = Buffer.from(envelope.signature as string, 'base64url');
  if (
    signature.length !== 64 ||
    signature.toString('base64url') !== envelope.signature ||
    !verify(
      null,
      Buffer.from(`runtime-import-v1\n${canonical(p)}`),
      createPublicKey({ key: Buffer.from(enrollment.publicKey, 'base64'), format: 'der', type: 'spki' }),
      signature,
    )
  )
    fault('NOT_AUTHORIZED', 403);
  return { payload: p, fingerprint: digest(p, 'runtime-import-intent-v1') };
}
