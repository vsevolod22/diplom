import 'reflect-metadata';
import assert from 'node:assert/strict';
import test from 'node:test';
import { ServiceUnavailableException } from '@nestjs/common';
import { ScansController } from './scans.controller.js';
import type { ScansService } from './scans.service.js';

test('controller delegates only verified identity to service; never enables 202', () => {
  const subject = { subject: 'alice', scope: ['scan:create'] };
  const service = { create(identity: unknown, body: unknown): never {
    assert.equal(identity, subject);
    assert.deepEqual(body, { imageReference: 'registry.example.com/a:v1' });
    throw new ServiceUnavailableException({ errorCode: 'SCANNER_UNAVAILABLE' });
  } } as ScansService;
  const controller = new ScansController(service);
  assert.throws(() => controller.create({ headers: {}, identity: subject }, { imageReference: 'registry.example.com/a:v1' }),
    error => error instanceof ServiceUnavailableException && error.getStatus() === 503);
});
