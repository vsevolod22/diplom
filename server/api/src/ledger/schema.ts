import { sql } from 'drizzle-orm';
import { check, integer, sqliteTable, text, unique } from 'drizzle-orm/sqlite-core';

// Scans/outbox baseline, unchanged through user_version=6. Runtime migrations in ledger.ts
// own the additional results/findings/events/audit tables; never auto-push this schema.
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
  check('scans_state_check', sql`${table.state} IN ('queued','running','completed','failed','cancelled')`),
]);

export const outbox = sqliteTable('outbox', {
  scanId: text('scan_id').primaryKey().references(() => scans.id),
  deliveredAt: text('delivered_at'),
  attempts: integer('attempts').notNull().default(0),
  leaseUntil: integer('lease_until'),
  nextRunAt: integer('next_run_at').notNull().default(0),
});
