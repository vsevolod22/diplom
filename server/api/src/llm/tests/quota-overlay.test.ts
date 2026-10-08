import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { quotaPolicyFromEnvironment } from '../quota-policy.js';
import { policyFromEnvironment } from '../policy.js';

test('fixed LOCAL overlay remains API-only/default-off with explicit caps; nonsecret template is not activation', () => {
  const overlay = readFileSync(new URL('../../../../deploy/compose.stand.openrouter.free.yaml', import.meta.url), 'utf8');
  const template = readFileSync(new URL('../../../../deploy/llm-quota.opt-in.example', import.meta.url), 'utf8');
  assert.match(overlay, /LLM_QUOTA_ENABLED: \$\{LLM_QUOTA_ENABLED:-false\}/);
  assert.match(overlay, /LLM_QUOTA_USER_INPUT: \$\{LLM_QUOTA_USER_INPUT:-\}/);
  assert.doesNotMatch(overlay, /LLM_QUOTA_DB_PATH|OPENROUTER_API_KEY:|worker:|mem_limit: 512m|auth_accounts:\/auth/);
  const env = Object.fromEntries(template.split('\n').filter(line => /^[A-Z_]+\d*=/i.test(line)).map(line => line.split('=', 2)));
  assert.equal(env.LLM_ENABLED, 'false'); assert.equal(env.LLM_ROUTING_APPROVED, 'false');
  assert.equal(quotaPolicyFromEnvironment(env), null);
  const bootstrap = { ...env, LLM_QUOTA_ENABLED: 'true' };
    assert.ok(quotaPolicyFromEnvironment(bootstrap));
    assert.equal(bootstrap.LLM_ENABLED, 'false'); assert.equal(bootstrap.LLM_ROUTING_APPROVED, 'false');
    assert.equal(policyFromEnvironment(bootstrap), null); // quota-only initialization is not generation permission
    const recipe = readFileSync(new URL('../TASK15.md', import.meta.url), 'utf8');
    assert.match(recipe, /\/app\/server\/api/); assert.match(recipe, /65532:65532/);
    assert.match(recipe, /mode0600/); assert.match(recipe, /LLM_QUOTA_ENABLED=true/);
    assert.match(recipe, /LLM_ENABLED=false/); assert.match(recipe, /LLM_ROUTING_APPROVED=false/);
    const image = readFileSync(new URL('../../../../deploy/api.Dockerfile', import.meta.url), 'utf8');
    assert.match(image, /COPY server\/api\/src server\/api\/src/);
    assert.match(image, /WORKDIR \/app\/server\/api\s+USER 65532:65532/);
  const nginx = readFileSync(new URL('../../../../deploy/stand.nginx.conf', import.meta.url), 'utf8');
  assert.match(nginx, /location \/api\/v1\/browser\/scans\/ \{\s+limit_except GET \{ deny all; \}/);
  assert.match(nginx, /proxy_read_timeout 15s;/);
});
