import { credentialDigest, type PolicyState } from '../src/policy.js';
export const A = 'a'.repeat(64);
export const B = 'b'.repeat(64);
export const TOKEN = 'c'.repeat(64);
export const route = (id = A, context = 'fixture') => `/v1/contexts/${context}/containers/${id}/inspect`;
export const request = () => ({ context: 'fixture', id: A, credential: TOKEN, grant: 'grant-a' });
export function fixtureState(socket: string): PolicyState {
  return {
    version: 1,
    callers: [{ id: 'caller-a', subject: 'subject-a', digest: credentialDigest(TOKEN) }],
    contexts: [{ id: 'fixture', version: 1, transport: 'unix', endpoint: socket, apiVersion: '1.47' }],
    consents: [
      {
        id: 'consent-a',
        caller: 'caller-a',
        subject: 'subject-a',
        version: 1,
        approved: true,
        revoked: false,
      },
    ],
    grants: [
      {
        id: 'grant-a',
        caller: 'caller-a',
        subject: 'subject-a',
        consent: 'consent-a',
        consentVersion: 1,
        context: 'fixture',
        contextVersion: 1,
        policyVersion: 1,
        version: 1,
        containerId: A,
        audience: 'inspect-broker',
        scope: 'container:inspect',
        notBefore: 100_000,
        expiresAt: 160_000,
        revoked: false,
      },
    ],
  };
}
export function inspect() {
  return { Id: A, Config: { User: '1000' }, HostConfig: { Privileged: true, ReadonlyRootfs: false } };
}
