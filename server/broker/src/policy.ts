import { createHash, timingSafeEqual } from 'node:crypto';
import { isAbsolute, normalize } from 'node:path';
import { HEX_ID, IDENTIFIER, type Target } from './contracts.js';

export interface Caller {
  id: string;
  subject: string;
  digest: string;
}
export interface Context {
  id: string;
  version: number;
  transport: 'unix' | 'unsupported';
  endpoint: string;
  apiVersion: '1.47';
}
export interface Consent {
  id: string;
  caller: string;
  subject: string;
  version: number;
  approved: boolean;
  revoked: boolean;
}
export interface Grant {
  id: string;
  caller: string;
  subject: string;
  consent: string;
  consentVersion: number;
  context: string;
  contextVersion: number;
  policyVersion: number;
  version: number;
  containerId: string;
  audience: string;
  scope: string;
  notBefore: number;
  expiresAt: number;
  revoked: boolean;
}
export interface PolicyState {
  version: number;
  callers: Caller[];
  contexts: Context[];
  consents: Consent[];
  grants: Grant[];
}
export interface Pin {
  epoch: number;
  subject: string;
  id: string;
  context: Readonly<Context>;
  grantVersion: number;
}
export function credentialDigest(credential: string): string {
  return createHash('sha256').update(credential, 'utf8').digest('hex');
}
const positive = (n: unknown) => Number.isSafeInteger(n) && Number(n) > 0;
const safe = (s: unknown) => typeof s === 'string' && IDENTIFIER.test(s);
const exact = (o: unknown, keys: string[]) =>
  !!o &&
  typeof o === 'object' &&
  !Array.isArray(o) &&
  Object.keys(o).length === keys.length &&
  Object.keys(o).every((key) => keys.includes(key));
function check(state: PolicyState): void {
  if (!exact(state, ['version', 'callers', 'contexts', 'consents', 'grants']) || !positive(state.version))
    throw new Error();
  for (const [items, max] of [
    [state.callers, 16],
    [state.contexts, 16],
    [state.consents, 64],
    [state.grants, 64],
  ] as const) {
    if (!Array.isArray(items) || items.length > max || new Set(items.map((v) => v?.id)).size !== items.length)
      throw new Error();
  }
  for (const c of state.callers)
    if (!exact(c, ['id', 'subject', 'digest']) || !safe(c.id) || !safe(c.subject) || !HEX_ID.test(c.digest))
      throw new Error();
  if (new Set(state.callers.map((c) => c.digest)).size !== state.callers.length) throw new Error();
  for (const c of state.contexts) {
    if (
      !exact(c, ['id', 'version', 'transport', 'endpoint', 'apiVersion']) ||
      !safe(c.id) ||
      !positive(c.version) ||
      c.apiVersion !== '1.47' ||
      !['unix', 'unsupported'].includes(c.transport) ||
      typeof c.endpoint !== 'string' ||
      c.endpoint.length > 100 ||
      (c.transport === 'unix' &&
        (!isAbsolute(c.endpoint) || normalize(c.endpoint) !== c.endpoint || /[\x00-\x1f]/.test(c.endpoint)))
    )
      throw new Error();
  }
  for (const c of state.consents)
    if (
      !exact(c, ['id', 'caller', 'subject', 'version', 'approved', 'revoked']) ||
      !safe(c.id) ||
      !safe(c.caller) ||
      !safe(c.subject) ||
      !positive(c.version) ||
      typeof c.approved !== 'boolean' ||
      typeof c.revoked !== 'boolean'
    )
      throw new Error();
  for (const g of state.grants) {
    if (
      !exact(g, [
        'id',
        'caller',
        'subject',
        'consent',
        'consentVersion',
        'context',
        'contextVersion',
        'policyVersion',
        'version',
        'containerId',
        'audience',
        'scope',
        'notBefore',
        'expiresAt',
        'revoked',
      ]) ||
      ![g.id, g.caller, g.subject, g.consent, g.context].every(safe) ||
      !HEX_ID.test(g.containerId) ||
      ![g.consentVersion, g.contextVersion, g.policyVersion, g.version].every(positive) ||
      typeof g.audience !== 'string' ||
      g.audience.length > 32 ||
      typeof g.scope !== 'string' ||
      g.scope.length > 32 ||
      !Number.isSafeInteger(g.notBefore) ||
      !Number.isSafeInteger(g.expiresAt) ||
      g.notBefore < 0 ||
      g.expiresAt <= g.notBefore ||
      g.expiresAt - g.notBefore > 300_000 ||
      typeof g.revoked !== 'boolean'
    )
      throw new Error();
  }
}

// Replacements and checks are synchronous on the same event loop as dispatch/publication.
// The input is never retained; callers cannot mutate an enrolled policy via object aliases.
export class PolicyStore {
  #state?: PolicyState;
  #epoch = 0;
  replace(input: PolicyState): void {
    this.#epoch++;
    this.#state = undefined;
    try {
      check(input);
      this.#state = structuredClone(input);
    } catch {
      throw new Error('invalid_policy');
    }
  }
  unavailable(): void {
    this.#epoch++;
    this.#state = undefined;
  }
  authorize(t: Target, now: number): Pin | undefined {
    const s = this.#state;
    if (
      !s ||
      !Number.isSafeInteger(now) ||
      !HEX_ID.test(t.id) ||
      !IDENTIFIER.test(t.context) ||
      !IDENTIFIER.test(t.grant) ||
      !HEX_ID.test(t.credential)
    )
      return;
    const digest = Buffer.from(credentialDigest(t.credential), 'hex');
    // Iterate all enrolled credentials, without a timing-dependent early match return.
    let caller: Caller | undefined;
    for (const c of s.callers) if (timingSafeEqual(Buffer.from(c.digest, 'hex'), digest)) caller = c;
    const g = s.grants.find((g) => g.id === t.grant);
    const c = s.contexts.find((c) => c.id === t.context);
    const consent = s.consents.find((v) => v.id === g?.consent);
    if (
      !caller ||
      !g ||
      !c ||
      !consent ||
      g.revoked ||
      consent.revoked ||
      !consent.approved ||
      g.caller !== caller.id ||
      g.subject !== caller.subject ||
      consent.caller !== caller.id ||
      consent.subject !== caller.subject ||
      g.audience !== 'inspect-broker' ||
      g.scope !== 'container:inspect' ||
      g.containerId !== t.id ||
      g.context !== c.id ||
      g.contextVersion !== c.version ||
      g.policyVersion !== s.version ||
      g.consentVersion !== consent.version ||
      now < g.notBefore ||
      now >= g.expiresAt
    )
      return;
    return Object.freeze({
      epoch: this.#epoch,
      subject: caller.subject,
      id: g.containerId,
      context: Object.freeze({ ...c }),
      grantVersion: g.version,
    });
  }
  recheck(t: Target, now: number, pin: Pin): Pin | undefined {
    const current = this.authorize(t, now);
    return current?.epoch === pin.epoch && current.grantVersion === pin.grantVersion ? current : undefined;
  }
}
