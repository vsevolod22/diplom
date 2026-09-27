import assert from 'node:assert/strict';
import test from 'node:test';
import { scannerFailure } from './scanner-errors.js';

test('scanner failure exposes allowlisted fields only, never raw signed URLs or stderr', () => {
  const failure = scannerFailure(17);
  assert.deepEqual(failure, { errorCode: 'SCAN_FAILED', stage: 'worker', exitCode: 17 });
  assert.deepEqual(scannerFailure(null, true), { errorCode: 'SCAN_TIMEOUT', stage: 'worker', exitCode: null });
  assert.equal(JSON.stringify(failure).includes('token'), false);
});
