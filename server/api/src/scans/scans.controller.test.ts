import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { ServiceUnavailableException } from '@nestjs/common';
import { ScansController } from './scans.controller.js';
import type { ScansService } from './scans.service.js';

test('controller delegates only verified identity to service; propagates fail-closed errors', async () => {
  const subject = { subject: 'alice', scope: ['scan:create'] };
  const service = { async create(identity: unknown, body: unknown) {
    assert.equal(identity, subject);
    assert.deepEqual(body, { imageReference: 'registry.example.com/a:v1' });
    throw new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
  } } as unknown as ScansService;
  const controller = new ScansController(service);
  await assert.rejects(controller.create({ headers: {}, identity: subject }, { imageReference: 'registry.example.com/a:v1' }),
    error => error instanceof ServiceUnavailableException && error.getStatus() === 503);
});
