import assert from 'node:assert/strict';
import test from 'node:test';
import { fork } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { FixtureQuotaLedger as QuotaLedger } from './quota-fixtures.js';
import { quotaPolicy } from './quota-fixtures.js';

async function barrier(path: string, actions: object[]) {
  const children = actions.map(() => fork(new URL('./quota-process.ts', import.meta.url), [path], { stdio: ['ignore', 'ignore', 'inherit', 'ipc'] }));
  const deadline = setTimeout(() => children.forEach(child => child.kill()), 10000);
  try {
    await Promise.all(children.map(child => new Promise<void>((resolve, reject) => {
      child.once('message', () => resolve()); child.once('error', reject); child.once('exit', code => { if (code) reject(new Error(`child ${code}`)); });
    })));
    return await Promise.all(children.map((child, index) => new Promise<{ result?: string | boolean; denied?: boolean }>((resolve, reject) => {
      child.once('message', value => resolve(value as { result?: string | boolean; denied?: boolean }));
      child.once('error', reject); child.send(actions[index]);
    })));
  } finally { clearTimeout(deadline); children.forEach(child => { if (child.connected) child.disconnect(); }); }
}

test('independent SQLite processes admit only one shared user reserve; dispatch-v-release CAS cannot double-send', { timeout: 15000 }, async () => {
  for (const scans of [['same-scan', 'same-scan'], ['scan-a', 'scan-b']]) {
    const dir = mkdtempSync(join(tmpdir(), 'quota-process-'));
    const path = join(dir, 'llm-usage.sqlite');
    const ledger = new QuotaLedger(path, quotaPolicy); ledger.close();
    try {
      const results = await barrier(path, scans.map(scan => ({ action: 'reserve', scan })));
      assert.equal(results.filter(r => typeof r.result === 'string').length, 1);
      assert.equal(results.filter(r => r.denied).length, 1);
      const id = results.find(r => typeof r.result === 'string')!.result as string;
      const race = await barrier(path, [{ action: 'dispatch', id }, { action: 'release', id }]);
      assert.equal(race.filter(r => r.result === true).length, 1);
      const reopened = new QuotaLedger(path, quotaPolicy);
      assert.equal(reopened.dispatch(id), false); assert.equal(reopened.release(id), false);
      const view = reopened.snapshot('shared-user', scans[results.findIndex(r => typeof r.result === 'string')]);
      assert.ok([0, 1000].includes(view.user.held.input));
      reopened.close();
    } finally { rmSync(dir, { recursive: true, force: true }); }
  }
});
