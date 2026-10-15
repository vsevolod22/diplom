import { createHmac, timingSafeEqual } from 'node:crypto';
import { canonical, exact, str, integer, target, HEX, ID, SLUG } from './contract.js';
import type { Invalidation, LiveIntent } from './live-port.js';
export function validateInvalidation(value: unknown): Invalidation {
  const f = exact(value, ['subject', 'consentId', 'epoch']);
  str(f.subject, /^[A-Za-z0-9:_-]{1,128}$/);
  str(f.consentId, ID);
  integer(f.epoch, 1);
  return f as Invalidation;
}
export function validateLiveIntent(value: unknown): LiveIntent {
  const i = exact(value, [
    'subject',
    'target',
    'consentId',
    'nonce',
    'expiresAt',
    'epoch',
    'brokerSubject',
    'captureId',
    'attempt',
  ]);
  validateInvalidation({ subject: i.subject, consentId: i.consentId, epoch: i.epoch });
  target(i.target);
  str(i.nonce, HEX);
  integer(i.expiresAt, 1);
  str(i.brokerSubject, SLUG);
  str(i.captureId, ID);
  integer(i.attempt, 1);
  return i as LiveIntent;
}
// Separate domain from the IPC bearer credential and broker grant. Entire closed intent is bound.
export function dispatchPermit(intent: LiveIntent, key: string): string {
  str(key, HEX);
  validateLiveIntent(intent);
  return createHmac('sha256', Buffer.from(key, 'hex'))
    .update(`runtime-dispatch-permit-v1\n${canonical(intent)}`)
    .digest('hex');
}
export function validDispatchPermit(intent: LiveIntent, key: string, permit: unknown): boolean {
  if (typeof permit !== 'string' || !HEX.test(permit)) return false;
  return timingSafeEqual(Buffer.from(permit, 'hex'), Buffer.from(dispatchPermit(intent, key), 'hex'));
}
