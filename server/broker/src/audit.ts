import { randomUUID } from 'node:crypto';
import { LIMITS, HEX_ID, IDENTIFIER, type Reason, type Status } from './contracts.js';
import type { Pin } from './policy.js';
export interface AuditRecord {
  correlationId: string;
  time: string;
  subject: string;
  containerId: string;
  context: string;
  operation: 'inspect';
  scope: 'container:inspect';
  stage: 'admission' | 'publication';
  decision: Status | 'allowed';
  reason: Reason;
  dispatched: boolean;
}
export interface AuditTicket {
  readonly key: symbol;
}
export class AuditBuffer {
  #records: AuditRecord[] = [];
  #reserved = new Set<symbol>();
  #available = true;
  readonly capacity: number;
  constructor(capacity: number = LIMITS.auditRecords) {
    if (!Number.isSafeInteger(capacity) || capacity < 2 || capacity > LIMITS.auditRecords)
      throw new Error('invalid_audit_capacity');
    this.capacity = capacity;
  }
  available(value: boolean): void {
    this.#available = value;
  }
  #accept(record: AuditRecord): boolean {
    if (!this.#available || !valid(record)) return false;
    this.#records.push(Object.freeze({ ...record }));
    return true;
  }
  deny(record: AuditRecord): boolean {
    return this.#records.length + this.#reserved.size < this.capacity && this.#accept(record);
  }
  reserve(record: AuditRecord): AuditTicket | undefined {
    if (this.#records.length + this.#reserved.size + 2 > this.capacity || !this.#accept(record)) return;
    const key = Symbol();
    this.#reserved.add(key);
    return { key };
  }
  finish(ticket: AuditTicket, record: AuditRecord): boolean {
    if (!this.#reserved.delete(ticket.key)) return false;
    return this.#accept(record);
  }
  correctPublication(correlationId: string, record: AuditRecord): boolean {
    if (!this.#available || !valid(record)) return false;
    const index = this.#records.findLastIndex(
      (r) => r.correlationId === correlationId && r.stage === 'publication',
    );
    if (index < 0) return false;
    this.#records[index] = Object.freeze({ ...record });
    return true;
  }
  // Trusted operator only; no network route. Reserved final records survive a drain.
  drain(): readonly AuditRecord[] {
    const records = this.#records;
    this.#records = [];
    return records;
  }
  get size(): number {
    return this.#records.length;
  }
  get reservations(): number {
    return this.#reserved.size;
  }
}
function valid(r: AuditRecord): boolean {
  const keys = [
    'correlationId',
    'time',
    'subject',
    'containerId',
    'context',
    'operation',
    'scope',
    'stage',
    'decision',
    'reason',
    'dispatched',
  ];
  return (
    !!r &&
    Object.keys(r).length === keys.length &&
    Object.keys(r).every((k) => keys.includes(k)) &&
    /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/.test(r.correlationId) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(r.time) &&
    IDENTIFIER.test(r.subject) &&
    (r.containerId === 'invalid' || HEX_ID.test(r.containerId)) &&
    IDENTIFIER.test(r.context) &&
    r.operation === 'inspect' &&
    r.scope === 'container:inspect' &&
    ['admission', 'publication'].includes(r.stage) &&
    ['allowed', 'checked', 'not_authorized', 'failed', 'unsupported'].includes(r.decision) &&
    [
      'allowed',
      'invalid_request',
      'authorization',
      'disabled',
      'overload',
      'audit_unavailable',
      'upstream',
      'cancelled',
      'deadline',
      'unsupported',
    ].includes(r.reason) &&
    typeof r.dispatched === 'boolean' &&
    Buffer.byteLength(JSON.stringify(r)) <= 1024
  );
}
export const correlation = () => randomUUID();
export function record(
  correlationId: string,
  now: number,
  pin: Pin | undefined,
  stage: AuditRecord['stage'],
  decision: AuditRecord['decision'],
  reason: Reason,
  dispatched: boolean,
): AuditRecord {
  return {
    correlationId,
    time: new Date(now).toISOString(),
    subject: pin?.subject ?? 'anonymous',
    containerId: pin?.id ?? 'invalid',
    context: pin?.context.id ?? 'invalid',
    operation: 'inspect',
    scope: 'container:inspect',
    stage,
    decision,
    reason,
    dispatched,
  };
}
