import assert from 'node:assert/strict';
import { randomUUID, createHash } from 'node:crypto';
import { mkdtempSync, rmSync, existsSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import Database from 'better-sqlite3';
import { HttpException } from '@nestjs/common';
import { HistoryStore } from '../history-store.js';
import { HistoryStore as Old4Store } from './reservation-v5-batch26-old4.fixture.js';
import { HISTORY, reportBinding, type Turn } from '../history-contract.js';
import { HISTORY_OWNER_CAPACITY } from '../history-capacity.js';
import { QuotaLedger } from '../quota-ledger.js';
import { quotaPolicyFromEnvironment } from '../quota-policy.js';
import { createOpenAiAccountingPolicy, createOpenAiQuotaContext, OPENAI_COST_BASIS } from '../openai-accounting.js';
import { prepareOpenAiSummary } from '../openai-prepared-request.js';
import { validateReply } from '../response.js';
import type { OpenAiSummaryPolicy } from '../provider-runtime-contract.js';
import { makeOpenAiPolicy, openAiReport, openAiReply } from './openai-core.fixture.js';
import { quotaEnv } from './quota-fixtures.js';

export const provider = makeOpenAiPolicy({ timeoutMs: 15000, monetaryLimit: 'uncapped', requestBudgetMicros: null });
export const policy: OpenAiSummaryPolicy = { provider: 'OpenAI', policy: provider, version: provider.version,
  findings: provider.findings, requestBytes: provider.requestBytes, responseBytes: provider.responseBytes };
export const owner = 'a'.repeat(32), report = openAiReport;
export const value = validateReply(openAiReply(), report, true);
export const quotaPolicy = quotaPolicyFromEnvironment({ ...quotaEnv, LLM_QUOTA_MONETARY_LIMIT: 'uncapped',
  LLM_QUOTA_USER_COST_USD: undefined, LLM_QUOTA_SCAN_COST_USD: undefined, LLM_QUOTA_OBSERVATION_COST_USD: undefined,
  LLM_QUOTA_OBSERVATION_COST_MICROS: '1000000' })!;
export const approval = createOpenAiAccountingPolicy({ enabled: true, revision: 'batch26-isolated', monetaryLimit: 'uncapped', providerPolicyVersion: provider.version,
  quotaPolicyVersion: quotaPolicy.version, billing: 'text-tokens-only-no-additional-fees', costBasis: OPENAI_COST_BASIS }, provider, quotaPolicy)!;
export function quotaContext(subject = owner) {
  const prepared = prepareOpenAiSummary(report, provider);
  return createOpenAiQuotaContext({ subject, scanId: report.scanId, reportVersion: report.reportVersion,
    policyVersion: provider.version, requestHash: prepared.hash }, prepared, provider, approval);
}
export const context = quotaContext();
export const capacity = (error: unknown) => error instanceof HttpException && error.getStatus() === 409 &&
  (error.getResponse() as { errorCode: string }).errorCode === 'LLM_HISTORY_CAPACITY';
export const conflict = (error: unknown) => error instanceof HttpException && error.getStatus() === 409;
export const unavailable = (error: unknown) => error instanceof HttpException && error.getStatus() === 503;
export function migrate(path: string) { HistoryStore.migrateSummaryReservations({ path }); }
export function tableRows(db: Database.Database, tables = ['history_meta', 'history_head', 'history_completion_space', 'llm_summary']) {
  return tables.map(table => db.prepare(`SELECT rowid,* FROM ${table} ORDER BY rowid`).all());
}
export function fingerprint(paths: string[]) {
  return paths.flatMap(path => ['', '-journal', '-wal', '-shm'].map(suffix => {
    const file = path + suffix;
    if (!existsSync(file)) return { file, exists: false };
    const stat = statSync(file, { bigint: true });
    return { file, size: stat.size, inode: stat.ino, mtime: stat.mtimeNs,
      hash: createHash('sha256').update(readFileSync(file)).digest('hex') };
  }));
}
export function fixture(version: 4 | 5 = 5) {
  const directory = mkdtempSync(join(tmpdir(), 'reservation-v5-batch26-'));
  const path = join(directory, 'llm-history.sqlite'), quotaPath = join(directory, 'llm-usage.sqlite');
  const old = new Old4Store(path, true); old.close();
  if (version === 5) migrate(path);
  const store = new HistoryStore(path), competitor = new HistoryStore(path), db = new Database(path);
  const ledger = new QuotaLedger(quotaPath, quotaPolicy, Date.now, true);
  return { directory, path, quotaPath, store, competitor, db, ledger,
    fillOwner(subject = owner, count = HISTORY_OWNER_CAPACITY.summaries - 1) {
      for (let i = 0; i < count; i++) {
        const other = { ...report, scanId: randomUUID() };
        store.writeSummary(subject, other, policy, { ...value, scanId: other.scanId });
      }
    },
    close() { ledger.close(); db.close(); competitor.close(); store.close(); rmSync(directory, { recursive: true, force: true }); } };
}
export function fillPhysical(store: HistoryStore, db: Database.Database) {
  let tail: { owner: string; scanId: string; epoch: string; revision: number } | undefined;
  let admitted = 0;
  for (let n = 0; n < HISTORY.heads; n++) {
    const subject = (n + 1).toString(16).padStart(32, '0'), scanId = randomUUID();
    const head = store.snapshot(subject, scanId), id = randomUUID();
    const turn: Turn = { id, mutationId: randomUUID(), state: 'pending', question: 'Проверить вручную.',
      report: reportBinding({ ...report, scanId }), createdAt: Date.now(), inputHash: 'f'.repeat(64),
      consentPolicyVersion: policy.version, requestHash: 'e'.repeat(64) };
    try {
      store.begin(subject, scanId, head.epoch, head.revision, turn, { id, sessionId: 'b'.repeat(32), generation: 1,
        accessIncarnation: 'c'.repeat(32), policyVersion: policy.version, deadline: Date.now() + 600000, requestHash: turn.requestHash });
      admitted++;
    } catch (error) { assert.ok(capacity(error)); tail = { owner: subject, scanId, epoch: head.epoch, revision: head.revision }; break; }
  }
  assert.ok(tail && admitted > 2 && admitted < HISTORY.heads, 'physical bound must stop real padded pending inserts before logical head limit');
  let full = false;
  for (let n = 0; n < HISTORY.decisions; n++) {
    try { tail.revision = store.decision(tail.owner, tail.scanId, tail.epoch, tail.revision, {
      id: randomUUID(), mutationId: randomUUID(), kind: 'user-decision', text: 'Проверить вручную. '.repeat(40),
      report: reportBinding({ ...report, scanId: tail.scanId }), sources: [] }).revision;
    } catch (error) { assert.ok(capacity(error)); full = true; break; }
  }
  assert.ok(full, 'small real decision writes must reach physical allocation failure');
  const writer = Reflect.get(store, 'db') as Database.Database;
  assert.equal(writer.pragma('max_page_count', { simple: true }), HISTORY.dbBytes / 4096, 'actual writer retains default 8MiB ceiling');
  assert.ok((db.pragma('page_count', { simple: true }) as number) * 4096 <= HISTORY.dbBytes);
  return admitted;
}
