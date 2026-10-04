import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { BadRequestException } from '@nestjs/common';
import { ScanLedger } from '../ledger/ledger.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from './oci-resolver.js';
import { ScansService } from '../scans/scans.service.js';
import { normalizeImageSuggestions, ImageSearchSessions } from '../scans/image-search.js';
import { NginxProofScansService } from './nginx-proof-profile.js';
import { NGINX_SUPPORTED_CANDIDATE as target, NGINX_ARCHIVE_TARGET } from './bounded-image-archive.js';

const reference = `${target.registry}/${target.repository}@${target.digest}`;
test('production is default-closed even with a seeded replay', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'nginx-policy-'));
  const ledger = new ScanLedger(join(directory, 'ledger.sqlite'));
  try {
    const store = { ledger } as LedgerStore;
    const resolver = { resolvePublicAlpine() { assert.fail('unsupported target must not resolve'); } } as unknown as OciResolver;
    const service = new ScansService(store, resolver);
    const proof = new NginxProofScansService(store, resolver);
    const request = { imageReference: reference, scope: 'image', checks: ['secret'], idempotencyKey: 'nginx-closed-replay' };
    const id = ledger.enqueue({ ...target, subject: 'owner', scope: 'image', checks: '["secret"]',
      idempotencyKey: request.idempotencyKey, fingerprint: 'a'.repeat(64) }).scanId;
    await assert.rejects(service.create({ subject: 'owner', scope: ['scan:create'] }, request), BadRequestException);
    for (const imageReference of [reference.replace(target.digest, NGINX_ARCHIVE_TARGET.digest), reference.replace('nginx', 'node'),
      'registry-1.docker.io/library/nginx:1.28-alpine', reference.replace(target.digest, `sha256:${'a'.repeat(64)}`)]) {
      await assert.rejects(proof.create({ subject: 'owner', scope: ['scan:create'] }, { ...request, imageReference }), BadRequestException);
    }
    assert.equal(ledger.findByKey('owner', request.idempotencyKey)?.scanId, id);
    const [suggestion] = normalizeImageSuggestions({ results: [{ repo_name: 'nginx' }], count: 1, next: null }, false);
    assert.equal(service.imageSuggestion(suggestion).scannable, false);
    assert.equal(proof.imageSuggestion(suggestion).reference, reference);
    const [unofficial] = normalizeImageSuggestions({ results: [{ repo_name: 'attacker/nginx' }], count: 1, next: null }, false);
    assert.equal(proof.imageSuggestion(unofficial).scannable, false);
    const sessions = new ImageSearchSessions(async () => ({ results: [{ repo_name: 'nginx' }, { repo_name: 'attacker/nginx' }], count: 2, next: null }),
      Date.now, item => proof.imageSuggestion(item));
    const page = await sessions.search('owner', 'nginx', 'generation');
    assert.equal(page.items[0].eligibility, 'isolated-exact-profile');
    assert.equal(page.items[1].scannable, false);
    assert.equal(page.loaded, 2);
  } finally { ledger.close(); rmSync(directory, { recursive: true, force: true }); }
});
