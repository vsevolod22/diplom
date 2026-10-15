import { createHash, sign, type KeyObject } from 'node:crypto';
import { canonical, capture, exact, payload, snapshot, type ImportPayload } from './contract.js';

const digest = (value: unknown, domain: string) =>
  createHash('sha256')
    .update(`${domain}\n${canonical(value)}`)
    .digest('hex');

// Operator-local packaging of ALREADY SANITIZED evidence, never a raw-inspect collector.
// A signature attests this enrolled source's statement; it is not TASK5/live acceptance.
export function createHistoricalPackage(input: unknown, privateKey: KeyObject) {
  const i = exact(input, [
    'snapshot',
    'startedAt',
    'running',
    'imageConfigDigest',
    'imageSemantics',
    'subject',
    'targetId',
    'targetVersion',
    'consentId',
    'nonce',
    'authorityEpoch',
    'signerId',
  ]);
  const s = snapshot(i.snapshot);
  const { hash: snapshotHash, ...snapshotBody } = s;
  if (
    createHash('sha256').update(canonical(snapshotBody)).digest('hex') !== snapshotHash ||
    privateKey.type !== 'private' ||
    privateKey.asymmetricKeyType !== 'ed25519'
  ) {
    throw new Error('INVALID_RUNTIME_INPUT');
  }
  const body = {
    schemaVersion: 'runtime-capture-v1',
    snapshot: s,
    startedAt: i.startedAt,
    endedAt: s.observedAt,
    running: i.running,
    imageConfigDigest: i.imageConfigDigest,
    imageSemantics: i.imageSemantics,
    binding: { nonce: i.nonce, consentId: i.consentId, authorityEpoch: i.authorityEpoch },
  };
  const evidence = capture({ ...body, hash: digest(body, 'runtime-capture-v1') });
  const p: ImportPayload = payload({
    schema: 'runtime-import-v1',
    subject: i.subject,
    targetId: i.targetId,
    targetVersion: i.targetVersion,
    consentId: i.consentId,
    nonce: i.nonce,
    signerId: i.signerId,
    sourceVersion: 'operator-runtime-v1',
    capture: evidence,
  });
  const result = {
    payload: p,
    hash: digest(p, 'runtime-import-v1'),
    signature: sign(null, Buffer.from(`runtime-import-v1\n${canonical(p)}`), privateKey).toString(
      'base64url',
    ),
  };
  if (Buffer.byteLength(canonical(result)) > 65000) throw new Error('INVALID_RUNTIME_INPUT');
  return result;
}
