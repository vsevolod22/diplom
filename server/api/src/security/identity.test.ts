import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import test from 'node:test';
import { verifyIdentity, InvalidIdentity } from './identity.js';
const config = { secret: 'dedicated-test-secret-not-for-production-12345', issuer: 'issuer.example', audience: 'scan-api', now: 1000 };
function token(payload: Record<string, unknown>, alg = 'HS256') {
  const body = `${Buffer.from(JSON.stringify({ typ: 'JWT', alg })).toString('base64url')}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}`;
  return `Bearer ${body}.${createHmac('sha256', config.secret).update(body).digest('base64url')}`;
}
const claims = { iss: config.issuer, aud: config.audience, sub: 'user:alice', iat: 900, exp: 1100, scope: 'scan:create' };
test('signed subject and scope, issuer, audience and expiry required', () => {
  assert.equal(verifyIdentity(token(claims), config).subject, 'user:alice');
  for (const change of [{ exp: 1000 }, { aud: 'other' }, { iss: 'other' }, { scope: 'read' }, { sub: '../admin' }]) {
    assert.throws(() => verifyIdentity(token({ ...claims, ...change }), config), InvalidIdentity);
  }
  assert.throws(() => verifyIdentity(token(claims, 'none'), config), InvalidIdentity);
  assert.throws(() => verifyIdentity(token(claims).replace(/.$/, 'x'), config), InvalidIdentity);
  assert.throws(() => verifyIdentity(undefined, config), InvalidIdentity);
});
