import 'reflect-metadata';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import type { ServerResponse } from 'node:http';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { BadRequestException, HttpException, NotFoundException } from '@nestjs/common';
import { ScanLedger } from '../ledger/ledger.js';
import type { LedgerStore } from '../ledger/ledger-store.js';
import type { OciResolver } from '../oci/oci-resolver.js';
import { ScansService } from './scans.service.js';

const identity = { subject: 'alice', scope: ['scan:create'] };
class Response extends EventEmitter {
  chunks: string[] = [];
  status = 0;
  destroyed = false;
  ended = false;
  writeHead(status: number) { this.status = status; return this; }
  write(chunk: string) { this.chunks.push(chunk); return true; }
  end() { this.ended = true; this.emit('close'); return this; }
  get text() { return this.chunks.join(''); }
  asServerResponse() { return this as unknown as ServerResponse; }
}

const setup = () => {
  const dir = mkdtempSync(join(tmpdir(), 'scan-events-'));
  const ledger = new ScanLedger(join(dir, 'db.sqlite'));
  const { scanId } = ledger.enqueue({ subject: 'alice', idempotencyKey: 'key', registry: 'registry-1.docker.io',
    repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' });
  const service = new ScansService({ ledger } as LedgerStore, {} as OciResolver);
  return { ledger, scanId, service, dispose: () => { ledger.close(); rmSync(dir, { recursive: true, force: true }); } };
};

test('durable replay is exclusive; terminal is last and reconnect after terminal is empty', () => {
  const { ledger, scanId, service, dispose } = setup();
  try {
    const queued = ledger.events(scanId, 'alice', null)![0];
    const job = ledger.claim()!;
    assert.equal(ledger.finishWithResult(scanId, job.attempts, [], '0.69.3'), true);
    const later = ledger.events(scanId, 'alice', queued.id)!;
    assert.deepEqual(later.map(e => e.state), ['running', 'completed']);
    assert.ok(later[0].id > queued.id && later[1].id > later[0].id);
    const replay = new Response();
    service.events(identity, scanId, String(queued.id), replay.asServerResponse());
    assert.equal(replay.status, 200);
    assert.equal(replay.ended, true);
    assert.doesNotMatch(replay.text, /"state":"queued"/);
    assert.ok(replay.text.includes(`id: ${later[1].id}\nevent: scan\ndata: {"scanId":"${scanId}","state":"completed","percent":null}`));
    const exhausted = new Response();
    service.events(identity, scanId, String(later[1].id), exhausted.asServerResponse());
    assert.equal(exhausted.ended, true);
    assert.doesNotMatch(exhausted.text, /event: scan/);
    assert.equal(service.status(identity, scanId).state, 'completed');
  } finally { dispose(); }
});

test('partial terminal event closes SSE on replay and after its final cursor', () => {
  const { ledger, service, dispose } = setup();
  try {
    const { scanId } = ledger.enqueue({ subject: 'alice', idempotencyKey: 'partial-key', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret","sbom"]', scope: 'image' });
    const queued = ledger.events(scanId, 'alice', null)![0];
    const job = ledger.claim()!;
    assert.equal(ledger.finishCombined(scanId, job.attempts, [
      { check: 'secret', outcome: 'checked', scannerVersion: '0.69.3', findings: [] },
      { check: 'sbom', outcome: 'failed', errorCode: 'SCAN_FAILED' },
    ]), true);
    const terminal = ledger.events(scanId, 'alice', queued.id)!.at(-1)!;
    assert.equal(terminal.state, 'partial');
    const replay = new Response();
    service.events(identity, scanId, String(queued.id), replay.asServerResponse());
    assert.equal(replay.ended, true);
    assert.match(replay.text, /"state":"partial","percent":null/);
    const exhausted = new Response();
    service.events(identity, scanId, String(terminal.id), exhausted.asServerResponse());
    assert.equal(exhausted.ended, true);
  } finally { dispose(); }
});

test('access and cursor are checked before writing headers; invalid and foreign IDs fail closed', () => {
  const { ledger, scanId, service, dispose } = setup();
  try {
    assert.equal(ledger.events(scanId, 'bob', null), undefined);
    for (const invalid of ['01', '-1', '9007199254740992', ['1', '2']]) {
      const response = new Response();
      assert.throws(() => service.events(identity, scanId, invalid, response.asServerResponse()), BadRequestException);
      assert.equal(response.status, 0);
    }
    const foreign = new Response();
    assert.throws(() => service.events({ subject: 'bob', scope: ['scan:create'] }, scanId, undefined, foreign.asServerResponse()), NotFoundException);
    assert.equal(foreign.status, 0);
  } finally { dispose(); }
});

test('rechecks ledger after attachment and continues through a terminal transition', () => {
  const { ledger, scanId, service, dispose } = setup();
  try {
    const original = ledger.events.bind(ledger);
    let reads = 0;
    ledger.events = ((...args: Parameters<ScanLedger['events']>) => {
      const result = original(...args);
      if (++reads === 1) {
        const job = ledger.claim()!;
        ledger.finishWithResult(scanId, job.attempts, [], '0.69.3');
      }
      return result;
    }) as ScanLedger['events'];
    const response = new Response();
    service.events(identity, scanId, undefined, response.asServerResponse());
    assert.equal(response.ended, true);
    assert.match(response.text, /"state":"completed","percent":null/);
    assert.equal((response.text.match(/event: scan/g) ?? []).length, 3);
    assert.ok(reads >= 2);
  } finally { dispose(); }
});

test('open stream polls through a later cancellation and closes after its final event', async () => {
  const { ledger, scanId, service, dispose } = setup();
  const response = new Response();
  try {
    service.events(identity, scanId, undefined, response.asServerResponse());
    assert.equal(response.ended, false);
    assert.match(response.text, /"state":"queued","percent":null/);
    assert.equal(ledger.cancel(scanId, 'alice'), 'cancelled');
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('SSE did not reach terminal')), 2500);
      response.once('close', () => { clearTimeout(timeout); resolve(); });
    });
    assert.match(response.text, /"state":"cancelled","percent":null/);
    assert.equal((response.text.match(/event: scan/g) ?? []).length, 2);
  } finally { response.emit('close'); dispose(); }
});

test('terminal committed after header and first event read is replayed on the next poll', async () => {
  const { ledger, scanId, service, dispose } = setup();
  const response = new Response();
  try {
    const state = ledger.state.bind(ledger);
    let stateReads = 0;
    ledger.state = ((...args: Parameters<ScanLedger['state']>) => {
      // events() checks state once before headers and once during the first poll.
      // Commit after that poll's event read, just before its terminal check.
      if (++stateReads === 3) ledger.cancel(scanId, 'alice');
      return state(...args);
    }) as ScanLedger['state'];
    service.events(identity, scanId, undefined, response.asServerResponse());
    assert.equal(response.status, 200);
    assert.equal(response.ended, false);
    await new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('post-header terminal event missed')), 2500);
      response.once('close', () => { clearTimeout(timeout); resolve(); });
    });
    assert.match(response.text, /"state":"cancelled","percent":null/);
    assert.equal((response.text.match(/event: scan/g) ?? []).length, 2);
  } finally { response.emit('close'); dispose(); }
});

test('ledger failure after headers emits only a sanitized SSE error and frees the slot', () => {
  const { ledger, scanId, service, dispose } = setup();
  try {
    const original = ledger.events.bind(ledger);
    let reads = 0;
    ledger.events = ((...args: Parameters<ScanLedger['events']>) => {
      if (++reads === 2) throw new Error('private db diagnostic');
      return original(...args);
    }) as ScanLedger['events'];
    const response = new Response();
    service.events(identity, scanId, undefined, response.asServerResponse());
    assert.equal(response.status, 200);
    assert.equal(response.ended, true);
    assert.match(response.text, /event: error\ndata: {"errorCode":"SCANNER_UNAVAILABLE"}/);
    assert.doesNotMatch(response.text, /private db diagnostic/);
    for (let i = 0; i < 6; i++) {
      const next = new Response();
      service.events(identity, scanId, undefined, next.asServerResponse());
      next.emit('close');
    }
  } finally { dispose(); }
});

test('per-subject and global quotas are released on disconnect without affecting other subjects', () => {
  const { ledger, scanId, service, dispose } = setup();
  const connections: Response[] = [];
  const open = (subject: string) => {
    const response = new Response();
    service.events({ subject, scope: ['scan:create'] }, scanId, undefined, response.asServerResponse());
    connections.push(response);
    return response;
  };
  const rejected = (subject: string) => {
    const response = new Response();
    assert.throws(() => service.events({ subject, scope: ['scan:create'] }, scanId, undefined, response.asServerResponse()),
      error => error instanceof HttpException && error.getStatus() === 429);
    assert.equal(response.status, 0);
  };
  try {
    for (let i = 0; i < 6; i++) open('alice');
    rejected('alice');
    // Other subjects can still connect; each has a real owned scan.
    const scanIds = new Map<string, string>();
    for (let i = 0; i < 58; i++) {
      const subject = `user-${Math.floor(i / 6)}`;
      let other = scanIds.get(subject);
      if (!other) {
        other = ledger.enqueue({ subject, idempotencyKey: 'key', registry: 'registry-1.docker.io',
          repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' }).scanId;
        scanIds.set(subject, other);
      }
      const response = new Response();
      service.events({ subject, scope: ['scan:create'] }, other, undefined, response.asServerResponse());
      connections.push(response);
    }
    const spareId = ledger.enqueue({ subject: 'spare', idempotencyKey: 'key', registry: 'registry-1.docker.io',
      repository: 'library/alpine', digest: `sha256:${'a'.repeat(64)}`, platform: 'linux/amd64', checks: '["secret"]' }).scanId;
    const full = new Response();
    assert.throws(() => service.events({ subject: 'spare', scope: ['scan:create'] }, spareId, undefined, full.asServerResponse()),
      error => error instanceof HttpException && error.getStatus() === 429);
    assert.equal(full.status, 0);
    const otherSubject = 'user-0';
    connections[6].emit('close');
    const reopened = new Response();
    service.events({ subject: otherSubject, scope: ['scan:create'] }, scanIds.get(otherSubject)!, undefined, reopened.asServerResponse());
    connections.push(reopened);
    connections[0].emit('close');
    const replacement = open('alice');
    assert.equal(replacement.ended, false);
    rejected('alice');
  } finally { for (const response of connections) response.emit('close'); dispose(); }
});

test('deadline ends the stream and releases the subject quota', t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const { scanId, service, dispose } = setup();
  try {
    const connections: Response[] = [];
    for (let i = 0; i < 6; i++) {
      const response = new Response();
      service.events(identity, scanId, undefined, response.asServerResponse());
      connections.push(response);
    }
    t.mock.timers.tick(120_000);
    assert.ok(connections.every(response => response.ended));
    const replacement = new Response();
    service.events(identity, scanId, undefined, replacement.asServerResponse());
    assert.equal(replacement.ended, false);
    replacement.emit('close');
  } finally { dispose(); }
});

test('terminal response releases both quota counters', async () => {
  const { ledger, scanId, service, dispose } = setup();
  const open: Response[] = [];
  try {
    for (let i = 0; i < 6; i++) {
      const response = new Response();
      service.events(identity, scanId, undefined, response.asServerResponse());
      open.push(response);
    }
    const closed = Promise.all(open.map(response => new Promise<void>(resolve => response.once('close', resolve))));
    const job = ledger.claim()!;
    ledger.finishWithResult(scanId, job.attempts, [], '0.69.3');
    let timeout: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([closed, new Promise<never>((_, reject) => {
        timeout = setTimeout(() => reject(new Error('streams did not close')), 2500);
      })]);
    } finally { if (timeout) clearTimeout(timeout); }
    for (let i = 0; i < 7; i++) {
      const response = new Response();
      service.events(identity, scanId, undefined, response.asServerResponse());
      assert.equal(response.ended, true);
    }
  } finally { for (const response of open) response.emit('close'); dispose(); }
});
