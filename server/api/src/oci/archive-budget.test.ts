import assert from 'node:assert/strict';
import test from 'node:test';
import { ArchiveAttemptBudget } from './archive-budget.js';
import { ARCHIVE_LIMITS as L } from './layer-tar-validator.js';
test('wire, successful-layer and reservation N/N+1 use one sticky attempt budget', () => {
  for (const [method, limit] of [['wire', L.wireBytes], ['layer', L.compressedTotal], ['reserve', L.scratchBytes]] as const) {
    const budget = new ArchiveAttemptBudget();
    budget[method](limit); assert.throws(() => budget[method](1)); assert.throws(() => budget.request());
  }
  const budget = new ArchiveAttemptBudget();
  budget.reserve(L.scratchBytes); budget.release(L.scratchBytes); budget.reserve(L.scratchBytes);
  assert.equal(budget.reservationPeak, L.scratchBytes);
  assert.throws(() => budget.release(L.scratchBytes + 1));
});
test('all auth/redirect/blob requests share N/N+1 and absolute deadline', () => {
  let now = 100;
  const budget = new ArchiveAttemptBudget(() => now);
  for (let index = 0; index < L.requests; index++) budget.request();
  assert.equal(budget.requests, L.requests); assert.throws(() => budget.request());
  const deadline = new ArchiveAttemptBudget(() => now);
  now += L.deadlineMs - 1; assert.equal(deadline.remaining(), 1);
  now++; assert.throws(() => deadline.wire(1)); assert.throws(() => deadline.request());
});
