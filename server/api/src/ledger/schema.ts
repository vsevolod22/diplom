import { sql } from 'drizzle-orm';
import { check, integer, sqliteTable, text, unique } from 'drizzle-orm/sqlite-core';

// Runtime migrations in ledger.ts exclusively own schema v15, including CVE policy binding and partial state
// and keyed scan_check_results. This is the query model, not an auto-push migration.
export const scans = sqliteTable('scans', {
  id: text('id').primaryKey(),
  subject: text('subject').notNull(),
  idempotencyKey: text('idempotency_key').notNull(),
  registry: text('registry').notNull(),
  repository: text('repository').notNull(),
  digest: text('digest').notNull(),
  platform: text('platform').notNull(),
  state: text('state').notNull(),
  createdAt: text('created_at').notNull().default(sql`CURRENT_TIMESTAMP`),
  fingerprint: text('fingerprint'),
  checks: text('checks').notNull().default('[]'),
  scope: text('scope').notNull().default('image'),
  terminalAt: text('terminal_at'),
}, table => [
  unique().on(table.subject, table.idempotencyKey),
  check('scans_state_check', sql`${table.state} IN ('queued','running','completed','failed','cancelled','partial')`),
]);

export const scanCvePolicy = sqliteTable('scan_cve_policy', {
  scanId: text('scan_id').primaryKey().references(() => scans.id),
  policy: text('policy').notNull(),
  resultContractVersion: integer('result_contract_version').notNull(),
});

export const scanCveEvidence = sqliteTable('scan_cve_evidence', {
  scanId: text('scan_id').primaryKey().references(() => scans.id),
  attempt: integer('attempt').notNull(),
  evidence: text('evidence').notNull(),
});

export const outbox = sqliteTable('outbox', {
  scanId: text('scan_id').primaryKey().references(() => scans.id),
  deliveredAt: text('delivered_at'),
  attempts: integer('attempts').notNull().default(0),
  leaseUntil: integer('lease_until'),
  leaseToken: text('lease_token'),
  nextRunAt: integer('next_run_at').notNull().default(0),
});
