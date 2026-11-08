import { createHash, randomUUID } from 'node:crypto';
import { closeSync, existsSync, lstatSync, openSync, realpathSync, statfsSync } from 'node:fs';
import { basename, dirname, resolve } from 'node:path';
import Database from 'better-sqlite3';
import { PUBLIC_FREE_OUTPUT_TOKENS } from './policy.js';
import { checkedOpenAiQuotaContext, checkedOpenAiQuotaUsage, type OpenAiQuotaContext } from './openai-accounting.js';
import type { OpenAiUsage } from './openai-usage.js';
import { checkedModuleApiQuotaContext, checkedModuleApiQuotaUsage, type ModuleApiQuotaContext } from './moduleapi-accounting.js';
import type { ModuleApiUsage } from './moduleapi-usage.js';
import { DAY, checkedQuotaMonetaryPolicy, integer, quotaExceeded, quotaUnavailable, type QuotaAdmission, type AdmissionSignal, type LimitVector, type MonetaryLimit, type QuotaPolicy, type UsageObservation, type Vector } from './quota-policy.js';

const APPLICATION = 1145655601;
const hash = (value: string) => createHash('sha256').update(value).digest('hex');

export type QuotaBindings = { subject: string; scanId: string; reportVersion: string; policyVersion: string; requestHash: string };
type Row = { id: string; state: string; window: number; expires: number; input: number; output: number; cost: number;
  reserve_input: number; reserve_output: number; reserve_cost: number; receipt: string | null;
  user_key: string; scan_key: string; report_hash: string; policy_hash: string; request_hash: string; quota_policy: string };
export type ScopeUsage = { limits: LimitVector; used: Vector; held: Vector; carried: Vector; remaining: LimitVector; warning: boolean; exhausted: boolean };
export type LifetimeBudget = { limitMicros: number; usedMicros: number; heldMicros: number; remainingMicros: number };
export type QuotaSnapshot = { admission: QuotaAdmission; monetaryLimit?: MonetaryLimit; lifetimeBudget?: LifetimeBudget;
  // With lifetimeBudget, daily token totals are counters, not admission limits.
  window: { start: number; end: number }; user: ScopeUsage; scan: ScopeUsage;
  reason: 'ready' | 'warning' | 'exhausted' | 'policy_fault';
  signals: Array<{ scope: 'user' | 'scan'; dimension: 'input' | 'output' | 'costMicros' | 'all'; reason: 'warning' | 'exhausted' | 'policy_fault' }> };

// A single immutable attempt row contributes to BOTH scopes; every insert/CAS is
// one SQLite transaction, not two independently updated process-local counters.
export class QuotaLedger {
  private readonly db: Database.Database;
  private readonly path: string;
  constructor(path: string, readonly policy: QuotaPolicy, private readonly clock: () => number = Date.now, initialize = false) {
    checkedQuotaMonetaryPolicy(policy);
    this.path = resolve(path);
    if (basename(this.path) !== 'llm-usage.sqlite' || realpathSync(dirname(this.path)) !== dirname(this.path)) throw quotaUnavailable();
    if (!existsSync(this.path)) {
      if (!initialize) throw quotaUnavailable();
      closeSync(openSync(this.path, 'wx', 0o600));
    }
    this.fileSafety();
    this.db = new Database(this.path, { timeout: policy.busyMs });
    try {
      const application = this.db.pragma('application_id', { simple: true });
      const version = this.db.pragma('user_version', { simple: true });
      if (initialize ? application !== 0 && application !== APPLICATION || version !== 0 && version !== 1 :
          application !== APPLICATION || version !== 1) throw quotaUnavailable();
      if (application === 0 && (this.db.prepare("SELECT count(*) AS n FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").get() as { n: number }).n !== 0) throw quotaUnavailable();
      this.db.pragma('page_size = 4096');
      if (this.db.pragma('page_size', { simple: true }) !== 4096) throw quotaUnavailable();
      this.db.pragma('journal_mode = DELETE'); this.db.pragma('synchronous = FULL');
      this.db.pragma('temp_store = MEMORY'); this.db.pragma('cache_size = -2048'); this.db.pragma('journal_size_limit = 0');
      this.db.pragma(`max_page_count = ${integer(policy.dbBytes / 4096, 16384)}`);
      if (initialize) this.db.transaction(() => {
        this.db.exec(`CREATE TABLE IF NOT EXISTS quota_meta (id INTEGER PRIMARY KEY CHECK(id=1), clock INTEGER NOT NULL) STRICT;
          INSERT OR IGNORE INTO quota_meta VALUES(1,0);
          CREATE TABLE IF NOT EXISTS quota_attempt (
            id TEXT PRIMARY KEY, user_key TEXT NOT NULL, scan_key TEXT NOT NULL,
            report_hash TEXT NOT NULL, policy_hash TEXT NOT NULL, request_hash TEXT NOT NULL,
            quota_policy TEXT NOT NULL, window INTEGER NOT NULL, expires INTEGER NOT NULL,
            state TEXT NOT NULL CHECK(state IN ('reserved','dispatched','settled','released','fault')),
            reserve_input INTEGER NOT NULL, reserve_output INTEGER NOT NULL, reserve_cost INTEGER NOT NULL,
            input INTEGER NOT NULL CHECK(input>=0), output INTEGER NOT NULL CHECK(output>=0), cost INTEGER NOT NULL CHECK(cost>=0),
            receipt TEXT
          ) STRICT;
          CREATE INDEX IF NOT EXISTS quota_user ON quota_attempt(user_key,window,state);
          CREATE INDEX IF NOT EXISTS quota_scan ON quota_attempt(scan_key,window,state);
          CREATE INDEX IF NOT EXISTS quota_cleanup ON quota_attempt(state,window);
          PRAGMA application_id = ${APPLICATION}; PRAGMA user_version = 1;`);
      }).immediate();
      if (this.db.pragma('quick_check', { simple: true }) !== 'ok') throw quotaUnavailable();
      this.safety();
    } catch { this.db.close(); throw quotaUnavailable(); }
  }
  close() { this.db.close(); }
    // New synchronous send guards use a tighter contention bound without changing
    // the accepted quota policy, accounting or ordinary summary connection default.
    withBusyTimeout<T>(busyMs: number, action: () => T): T {
      if (!Number.isInteger(busyMs) || busyMs < 0 || busyMs > this.policy.busyMs) throw quotaUnavailable();
      const previous = this.db.pragma('busy_timeout', { simple: true }) as number;
      try {
        this.db.pragma(`busy_timeout = ${busyMs}`);
        const result = action();
        if (result && typeof result === 'object' && 'then' in result) throw quotaUnavailable();
        return result;
      } finally { this.db.pragma(`busy_timeout = ${previous}`); }
    }
  private fileSafety() {
    const stat = lstatSync(this.path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || (stat.mode & 0o077) !== 0 ||
      process.getuid && stat.uid !== process.getuid() || stat.size > this.policy.dbBytes) throw quotaUnavailable();
    for (const suffix of ['-journal', '-wal', '-shm']) {
      const path = this.path + suffix;
      if (!existsSync(path)) continue;
      const sidecar = lstatSync(path);
      if (!sidecar.isFile() || sidecar.isSymbolicLink() || sidecar.nlink !== 1 || sidecar.size > this.policy.dbBytes + 1048576 ||
          (sidecar.mode & 0o077) !== 0 || process.getuid && sidecar.uid !== process.getuid() || suffix !== '-journal') throw quotaUnavailable();
    }
    const fs = statfsSync(dirname(this.path), { bigint: true });
    if (fs.bavail * fs.bsize < BigInt(this.policy.diskHeadroomBytes)) throw quotaUnavailable();
  }
  private safety() {
    this.fileSafety();
    const pages = Number(this.db.pragma('page_count', { simple: true }));
    if (!Number.isSafeInteger(pages) || pages * 4096 > this.policy.dbBytes) throw quotaUnavailable();
    const count = (this.db.prepare('SELECT count(*) AS n FROM quota_attempt').get() as { n: number }).n;
    if (integer(count, 100000) + 1 > this.policy.maxRows) throw quotaUnavailable();
  }
  private time(): number {
    const time = integer(this.clock(), 8640000000000000);
    const previous = (this.db.prepare('SELECT clock FROM quota_meta WHERE id=1').get() as { clock: number }).clock;
    if (time < previous) throw quotaUnavailable();
    return time;
  }
  private write<T>(operation: () => T): T {
    try {
      return this.db.transaction(() => {
        this.fileSafety();
        const result = operation();
        this.safety();
        return result;
      }).immediate();
    } catch (error) {
      if (error instanceof Error && 'getStatus' in error) throw error;
      throw quotaUnavailable();
    }
  }
  private scope(key: 'user_key' | 'scan_key', value: string, window: number, limits: LimitVector): ScopeUsage {
    const aggregate = (condition: string): Vector => {
      const row = this.db.prepare(`SELECT coalesce(sum(input),0) AS input, coalesce(sum(output),0) AS output,
        coalesce(sum(cost),0) AS costMicros FROM quota_attempt WHERE ${key}=? AND ${condition}`).get(value, window) as Vector;
      // SUM can outgrow the policy cap under known overages, but stays inside a
      // safe integer even at the configured maximum rows/observation ceilings.
      return { input: integer(row.input, Number.MAX_SAFE_INTEGER), output: integer(row.output, Number.MAX_SAFE_INTEGER), costMicros: integer(row.costMicros, Number.MAX_SAFE_INTEGER) };
    };
    const used = aggregate("window=? AND state='settled'");
    const held = aggregate("window=? AND state IN ('reserved','dispatched','fault')");
    const carried = aggregate("window<? AND state IN ('reserved','dispatched','fault')");
    const total = (dimension: keyof Vector) => integer(used[dimension] + held[dimension] + carried[dimension], Number.MAX_SAFE_INTEGER);
    const remaining = { input: Math.max(0, limits.input - total('input')), output: Math.max(0, limits.output - total('output')),
      costMicros: limits.costMicros === null ? null : Math.max(0, limits.costMicros - total('costMicros')) };
    return { limits, used, held, carried, remaining,
      warning: (['input', 'output', 'costMicros'] as const).some(d => {
        const cap = limits[d];
        return cap !== null && cap > 0 && total(d) >= cap * this.policy.warningPercent / 100;
      }),
      exhausted: remaining.input === 0 || remaining.output === 0 || limits.costMicros !== null &&
        (total('costMicros') > limits.costMicros || limits.costMicros > 0 && remaining.costMicros === 0) };
  }
  private lifetimeBudget(userKey: string): LifetimeBudget | undefined {
    const limitMicros = this.policy.lifetimeUserCostMicros;
    if (limitMicros === undefined) return undefined;
    // No window, scan or policy filter: old paid/free policies and unknown sends
    // remain account liabilities after a policy switch or calendar rollover.
    const row = this.db.prepare(`SELECT coalesce(sum(CASE WHEN state='settled' THEN cost ELSE 0 END),0) AS usedMicros,
      coalesce(sum(CASE WHEN state IN ('reserved','dispatched','fault') THEN cost ELSE 0 END),0) AS heldMicros
      FROM quota_attempt WHERE user_key=?`).get(userKey) as { usedMicros: number; heldMicros: number };
    const usedMicros = integer(row.usedMicros, Number.MAX_SAFE_INTEGER), heldMicros = integer(row.heldMicros, Number.MAX_SAFE_INTEGER);
    const total = integer(usedMicros + heldMicros, Number.MAX_SAFE_INTEGER);
    return { limitMicros, usedMicros, heldMicros, remainingMicros: Math.max(0, limitMicros - total) };
  }
  private validateReserve(reserve: Vector, paid = false): void {
    checkedQuotaMonetaryPolicy(this.policy);
    // The uncapped mode is an opt-in paid seam, never a widening of freeOnly.
    if (!paid && this.policy.monetaryLimit === 'uncapped') throw quotaUnavailable();
    integer(reserve.input, this.policy.requestInput);
    integer(reserve.output, paid ? 4096 : PUBLIC_FREE_OUTPUT_TOKENS);
    integer(reserve.costMicros, paid ? this.policy.observationCostMicros : 0);
    if (reserve.input === 0 || reserve.output === 0 || paid && reserve.costMicros === 0) throw quotaUnavailable();
  }
  private admission(user: ScopeUsage, scan: ScopeUsage, userFault: boolean, scanFault: boolean, reserve?: Vector, paid = false,
    lifetimeBudget?: LifetimeBudget): QuotaAdmission {
      if (!reserve) return { status: 'unavailable' };
      // Storage admits the largest supported envelope; preparation/runtime still
      // enforce the narrower legacy profile ceiling before producing a vector.
      this.validateReserve(reserve, paid);
      const signals: AdmissionSignal[] = [];
      for (const [name, scope, fault] of [['user', user, userFault], ['scan', scan, scanFault]] as const) {
        if (fault) signals.push({ scope: name, dimension: 'all', reason: 'policy_fault' });
        if (lifetimeBudget) continue;
        for (const dimension of ['input', 'output', 'costMicros'] as const) {
          const remaining = scope.remaining[dimension];
          if (remaining !== null && reserve[dimension] > remaining) signals.push({ scope: name, dimension, reason: 'insufficient',
            required: reserve[dimension], remaining });
        }
      }
      if (lifetimeBudget && reserve.costMicros > lifetimeBudget.remainingMicros)
        signals.push({ scope: 'user', dimension: 'costMicros', reason: 'insufficient',
          required: reserve.costMicros, remaining: lifetimeBudget.remainingMicros });
      return Object.freeze({ status: userFault || scanFault ? 'policy_fault' : signals.length ? 'insufficient' : 'fits',
        reserve: Object.freeze({ ...reserve }), signals: Object.freeze(signals.map(s => Object.freeze(s))) });
    }
    private snapshotAt(subject: string, scanId: string, time: number, reserve?: Vector, paid = false): QuotaSnapshot {
    const window = Math.floor(time / DAY) * DAY;
    const userKey = hash(subject), scanKey = hash(JSON.stringify([subject, scanId]));
    const user = this.scope('user_key', userKey, window, this.policy.user), scan = this.scope('scan_key', scanKey, window, this.policy.scan);
    const lifetimeBudget = this.lifetimeBudget(userKey);
    if (lifetimeBudget) for (const scope of [user, scan]) {
      scope.exhausted = lifetimeBudget.remainingMicros === 0;
      scope.warning = lifetimeBudget.usedMicros + lifetimeBudget.heldMicros >= lifetimeBudget.limitMicros * this.policy.warningPercent / 100;
    }
    const userFault = this.db.prepare("SELECT 1 FROM quota_attempt WHERE state='fault' AND user_key=? LIMIT 1").get(userKey);
    const scanFault = this.db.prepare("SELECT 1 FROM quota_attempt WHERE state='fault' AND scan_key=? LIMIT 1").get(scanKey);
    const signals: QuotaSnapshot['signals'] = [];
    for (const [name, scope, fault] of [['user', user, userFault], ['scan', scan, scanFault]] as const) {
      if (fault) signals.push({ scope: name, dimension: 'all', reason: 'policy_fault' });
      if (lifetimeBudget) continue;
      for (const dimension of ['input', 'output', 'costMicros'] as const) {
        const total = scope.used[dimension] + scope.held[dimension] + scope.carried[dimension];
        const cap = scope.limits[dimension];
        if (cap === null) continue;
        const exhausted = scope.remaining[dimension] === 0 && (dimension !== 'costMicros' || cap > 0 || total > 0);
        if (exhausted) signals.push({ scope: name, dimension, reason: 'exhausted' });
        else if (cap > 0 && total >= cap * this.policy.warningPercent / 100)
          signals.push({ scope: name, dimension, reason: 'warning' });
      }
    }
    if (lifetimeBudget && (user.exhausted || user.warning))
      signals.push({ scope: 'user', dimension: 'costMicros', reason: user.exhausted ? 'exhausted' : 'warning' });
    return { admission: this.admission(user, scan, !!userFault, !!scanFault, reserve, paid, lifetimeBudget),
      ...(lifetimeBudget ? { lifetimeBudget } : {}),
      ...(this.policy.monetaryLimit !== undefined ? { monetaryLimit: this.policy.monetaryLimit } : {}),
      window: { start: window, end: window + DAY }, user, scan, signals,
      reason: userFault || scanFault ? 'policy_fault' : user.exhausted || scan.exhausted ? 'exhausted' : user.warning || scan.warning ? 'warning' : 'ready' };
  }
  snapshot(subject: string, scanId: string, reserve?: Vector): QuotaSnapshot {
    try { return this.db.transaction(() => { this.safety(); return this.snapshotAt(subject, scanId, this.time(), reserve); })(); }
    catch { throw quotaUnavailable(); }
  }
  reserve(binding: QuotaBindings, reserve: Vector): string {
    return this.reserveAttempt(binding, reserve);
  }
  private reserveAttempt(binding: QuotaBindings, reserve: Vector, paidPolicySnapshot?: string): string {
    return this.write(() => {
      // The authoritative clock is intentionally sampled AFTER BEGIN IMMEDIATE.
      const time = this.time();
      if (!binding.subject || binding.subject.length > 200 || !binding.scanId || binding.scanId.length > 200 ||
          ![binding.reportVersion, binding.policyVersion, binding.requestHash].every(v => /^[a-f0-9]{64}$/.test(v))) throw quotaUnavailable();
      this.validateReserve(reserve, paidPolicySnapshot !== undefined);
      // Retain settlements even while lifetime enforcement is disabled, so a later
      // enable cannot erase spend. Rows deleted by older cleanup are unrecoverable;
      // lifetime totals can only include retained history. Released rows owe zero.
      this.db.prepare(`DELETE FROM quota_attempt WHERE id IN (SELECT id FROM quota_attempt
        WHERE state='released' AND cost=0 AND window+?<? LIMIT ?)`)
        .run(DAY * (1 + this.policy.replayDays), time, this.policy.cleanupBatch);
      const view = this.snapshotAt(binding.subject, binding.scanId, time, reserve, paidPolicySnapshot !== undefined);
      if (view.admission.status !== 'fits') throw quotaExceeded(view.admission);
      const id = randomUUID();
      this.db.prepare(`INSERT INTO quota_attempt VALUES(?,?,?,?,?,?,?,?,?,'reserved',?,?,?,?,?,?,NULL)`).run(
        id, hash(binding.subject), hash(JSON.stringify([binding.subject, binding.scanId])), binding.reportVersion, binding.policyVersion,
        binding.requestHash, paidPolicySnapshot ?? JSON.stringify(this.policy), view.window.start, time + this.policy.receiptMs,
        reserve.input, reserve.output, reserve.costMicros, reserve.input, reserve.output, reserve.costMicros);
      this.db.prepare('UPDATE quota_meta SET clock=? WHERE id=1').run(time);
      return id;
    });
  }
  // Schema v1 already stores the original policy as JSON. This is an additive
  // payload contract, not a DDL migration. Never run old free-only writers against
  // paid rows: they cannot enforce the separate receipt semantics below.
  private openAiPolicySnapshot(context: OpenAiQuotaContext): string {
    const { quota } = checkedOpenAiQuotaContext(context);
    return JSON.stringify({ ...quota, paidAccounting: context.accounting });
  }
  private currentOpenAiPolicy(context: OpenAiQuotaContext): void {
    const { quota } = checkedOpenAiQuotaContext(context);
    if (JSON.stringify(quota) !== JSON.stringify(this.policy)) throw quotaUnavailable();
  }
  private openAiRow(id: string, context: OpenAiQuotaContext): Row | undefined {
    const snapshot = this.openAiPolicySnapshot(context), binding = context.binding;
    const row = this.db.prepare('SELECT * FROM quota_attempt WHERE id=?').get(id) as Row | undefined;
    if (!row || row.quota_policy !== snapshot || row.user_key !== hash(binding.subject) ||
        row.scan_key !== hash(JSON.stringify([binding.subject, binding.scanId])) || row.report_hash !== binding.reportVersion ||
        row.policy_hash !== binding.policyVersion || row.request_hash !== binding.requestHash ||
        row.reserve_input !== context.reserve.input || row.reserve_output !== context.reserve.output ||
        row.reserve_cost !== context.reserve.costMicros) return undefined;
    return row;
  }
  snapshotOpenAi(context: OpenAiQuotaContext): QuotaSnapshot {
    this.currentOpenAiPolicy(context);
    try {
      return this.db.transaction(() => {
        this.safety();
        return this.snapshotAt(context.binding.subject, context.binding.scanId, this.time(), context.reserve, true);
      })();
    } catch { throw quotaUnavailable(); }
  }
  reserveOpenAi(context: OpenAiQuotaContext): string {
    this.currentOpenAiPolicy(context);
    return this.reserveAttempt(context.binding, context.reserve, this.openAiPolicySnapshot(context));
  }
  assertOpenAiReserved(id: string, context: OpenAiQuotaContext): boolean {
    this.currentOpenAiPolicy(context);
    try {
      return this.db.transaction(() => {
        this.safety();
        const row = this.openAiRow(id, context);
        return !!row && row.state === 'reserved' && row.expires >= this.time();
      })();
    } catch { throw quotaUnavailable(); }
  }
  dispatchOpenAi(id: string, context: OpenAiQuotaContext): boolean {
    this.currentOpenAiPolicy(context);
    return this.write(() => {
      const time = this.time(), row = this.openAiRow(id, context);
      if (!row || row.state !== 'reserved' || row.expires < time) return false;
      const dispatched = this.db.prepare("UPDATE quota_attempt SET state='dispatched' WHERE id=? AND state='reserved'").run(id).changes === 1;
      this.db.prepare('UPDATE quota_meta SET clock=? WHERE id=1').run(time);
      return dispatched;
    });
  }
  dispatchOpenAiGuarded(id: string, context: OpenAiQuotaContext, beforeSend: () => void, send: () => void): boolean {
    if (!this.dispatchOpenAi(id, context)) return false;
    try {
      const result: unknown = beforeSend();
      if (result !== undefined) {
        // Consume rejected promises/thenables without trusting an arbitrary .catch.
        void new Promise<unknown>(resolve => resolve(result)).catch(() => {});
        throw quotaUnavailable();
      }
    } catch (error) {
      // Only this call's fresh dispatch is known unsent. Recheck the exact branded
      // binding and receipt under the write lock; never expose a general refund.
      try {
        this.write(() => {
          const row = this.openAiRow(id, context);
          if (!row || row.state !== 'dispatched' || row.receipt !== null) return;
          this.db.prepare(`UPDATE quota_attempt SET state='released',input=0,output=0,cost=0
            WHERE id=? AND state='dispatched' AND receipt IS NULL`).run(id);
        });
      } catch { /* Failed compensation retains liability and the original rejection. */ }
      throw error;
    }
    // Entry into send ends the proof of non-dispatch, even if send itself throws.
    send();
    return true;
  }
  releaseOpenAi(id: string, context: OpenAiQuotaContext): boolean {
    return this.write(() => this.openAiRow(id, context) !== undefined && this.releaseReserved(id));
  }
  observeOpenAi(id: string, context: OpenAiQuotaContext, observation: OpenAiUsage): boolean {
    checkedOpenAiQuotaUsage(context, observation);
    return this.write(() => {
      const row = this.openAiRow(id, context);
      if (!row) return false;
      const receipt = hash(JSON.stringify([context.accounting, observation.source, observation.normal,
        observation.input ?? null, observation.output ?? null, observation.costMicros ?? null]));
      if (row.state === 'settled' || row.state === 'fault') return row.state === 'settled' && row.receipt === receipt;
      const time = this.time();
      if (row.state !== 'dispatched' || time > row.expires) return false;
      // Bounds and price provenance belong to the reservation, NOT the currently
      // selected provider/policy. Known overages remain liabilities even above a
      // configured observation ceiling; only settlement is disallowed then.
      const { quota } = checkedOpenAiQuotaContext(context);
      const input = observation.input === undefined ? undefined : integer(observation.input, 1_048_576);
      const output = observation.output === undefined ? undefined : integer(observation.output, 1_048_576);
      const cost = observation.costMicros === undefined ? undefined : integer(observation.costMicros, Number.MAX_SAFE_INTEGER);
      const normal = observation.normal && input !== undefined && output !== undefined && cost !== undefined &&
        input <= row.reserve_input && output <= row.reserve_output && cost <= row.reserve_cost &&
        input <= quota.observationTokens && output <= quota.observationTokens && cost <= quota.observationCostMicros;
      if (!normal && input === undefined && output === undefined && cost === undefined) return false;
      this.db.prepare(`UPDATE quota_attempt SET state=?,input=?,output=?,cost=?,receipt=? WHERE id=? AND state='dispatched'`).run(
        normal ? 'settled' : 'fault', normal ? input : Math.max(row.reserve_input, input ?? 0),
        normal ? output : Math.max(row.reserve_output, output ?? 0), normal ? cost : Math.max(row.reserve_cost, cost ?? 0), receipt, id);
      this.db.prepare('UPDATE quota_meta SET clock=? WHERE id=1').run(time);
      return normal;
    });
  }
  // Separate branded ModuleAPI receipts, same transaction and historical account totals.
  private moduleApiPolicySnapshot(context: ModuleApiQuotaContext): string {
    const { quota } = checkedModuleApiQuotaContext(context);
    return JSON.stringify({ ...quota, paidAccounting: context.accounting });
  }
  private currentModuleApiPolicy(context: ModuleApiQuotaContext): void {
    const { quota } = checkedModuleApiQuotaContext(context);
    if (JSON.stringify(quota) !== JSON.stringify(this.policy)) throw quotaUnavailable();
  }
  private moduleApiRow(id: string, context: ModuleApiQuotaContext): Row | undefined {
    const snapshot = this.moduleApiPolicySnapshot(context), binding = context.binding;
    const row = this.db.prepare('SELECT * FROM quota_attempt WHERE id=?').get(id) as Row | undefined;
    if (!row || row.quota_policy !== snapshot || row.user_key !== hash(binding.subject) ||
        row.scan_key !== hash(JSON.stringify([binding.subject, binding.scanId])) || row.report_hash !== binding.reportVersion ||
        row.policy_hash !== binding.policyVersion || row.request_hash !== binding.requestHash ||
        row.reserve_input !== context.reserve.input || row.reserve_output !== context.reserve.output ||
        row.reserve_cost !== context.reserve.costMicros) return undefined;
    return row;
  }
  snapshotModuleApi(context: ModuleApiQuotaContext): QuotaSnapshot {
    this.currentModuleApiPolicy(context);
    try {
      return this.db.transaction(() => {
        this.safety();
        return this.snapshotAt(context.binding.subject, context.binding.scanId, this.time(), context.reserve, true);
      })();
    } catch { throw quotaUnavailable(); }
  }
  reserveModuleApi(context: ModuleApiQuotaContext): string {
    this.currentModuleApiPolicy(context);
    return this.reserveAttempt(context.binding, context.reserve, this.moduleApiPolicySnapshot(context));
  }
  assertModuleApiReserved(id: string, context: ModuleApiQuotaContext): boolean {
    this.currentModuleApiPolicy(context);
    try {
      return this.db.transaction(() => {
        this.safety();
        const row = this.moduleApiRow(id, context);
        return !!row && row.state === 'reserved' && row.expires >= this.time();
      })();
    } catch { throw quotaUnavailable(); }
  }
  dispatchModuleApi(id: string, context: ModuleApiQuotaContext): boolean {
    this.currentModuleApiPolicy(context);
    return this.write(() => {
      const time = this.time(), row = this.moduleApiRow(id, context);
      if (!row || row.state !== 'reserved' || row.expires < time) return false;
      const dispatched = this.db.prepare("UPDATE quota_attempt SET state='dispatched' WHERE id=? AND state='reserved'").run(id).changes === 1;
      this.db.prepare('UPDATE quota_meta SET clock=? WHERE id=1').run(time);
      return dispatched;
    });
  }
  dispatchModuleApiGuarded(id: string, context: ModuleApiQuotaContext, beforeSend: () => void, send: () => void): boolean {
    if (!this.dispatchModuleApi(id, context)) return false;
    try {
      const result: unknown = beforeSend();
      if (result !== undefined) {
        // Consume rejected promises/thenables without trusting an arbitrary .catch.
        void new Promise<unknown>(resolve => resolve(result)).catch(() => {});
        throw quotaUnavailable();
      }
    } catch (error) {
      // Only this call's fresh dispatch is known unsent. Recheck the exact branded
      // binding and receipt under the write lock; never expose a general refund.
      try {
        this.write(() => {
          const row = this.moduleApiRow(id, context);
          if (!row || row.state !== 'dispatched' || row.receipt !== null) return;
          this.db.prepare(`UPDATE quota_attempt SET state='released',input=0,output=0,cost=0
            WHERE id=? AND state='dispatched' AND receipt IS NULL`).run(id);
        });
      } catch { /* Failed compensation retains liability and the original rejection. */ }
      throw error;
    }
    // Entry into send ends the proof of non-dispatch, even if send itself throws.
    send();
    return true;
  }
  releaseModuleApi(id: string, context: ModuleApiQuotaContext): boolean {
    return this.write(() => this.moduleApiRow(id, context) !== undefined && this.releaseReserved(id));
  }
  observeModuleApi(id: string, context: ModuleApiQuotaContext, observation: ModuleApiUsage): boolean {
    checkedModuleApiQuotaUsage(context, observation);
    return this.write(() => {
      const row = this.moduleApiRow(id, context);
      if (!row) return false;
      const receipt = hash(JSON.stringify([context.accounting, observation.source, observation.normal,
        observation.input ?? null, observation.output ?? null, observation.costMicros ?? null]));
      if (row.state === 'settled' || row.state === 'fault') return row.state === 'settled' && row.receipt === receipt;
      const time = this.time();
      if (row.state !== 'dispatched' || time > row.expires) return false;
      // Bounds and price provenance belong to the reservation, NOT the currently
      // selected provider/policy. Known overages remain liabilities even above a
      // configured observation ceiling; only settlement is disallowed then.
      const { quota } = checkedModuleApiQuotaContext(context);
      const input = observation.input === undefined ? undefined : integer(observation.input, 1_048_576);
      const output = observation.output === undefined ? undefined : integer(observation.output, 1_048_576);
      const cost = observation.costMicros === undefined ? undefined : integer(observation.costMicros, Number.MAX_SAFE_INTEGER);
      const normal = observation.normal && input !== undefined && output !== undefined && cost !== undefined &&
        input <= row.reserve_input && output <= row.reserve_output && cost <= row.reserve_cost &&
        input <= quota.observationTokens && output <= quota.observationTokens && cost <= quota.observationCostMicros;
      if (!normal && input === undefined && output === undefined && cost === undefined) return false;
      this.db.prepare(`UPDATE quota_attempt SET state=?,input=?,output=?,cost=?,receipt=? WHERE id=? AND state='dispatched'`).run(
        normal ? 'settled' : 'fault', normal ? input : Math.max(row.reserve_input, input ?? 0),
        normal ? output : Math.max(row.reserve_output, output ?? 0), normal ? cost : Math.max(row.reserve_cost, cost ?? 0), receipt, id);
      this.db.prepare('UPDATE quota_meta SET clock=? WHERE id=1').run(time);
      return normal;
    });
  }
  private freeRow(row: Row): boolean {
    return row.reserve_cost === 0 && !Object.hasOwn(JSON.parse(row.quota_policy), 'paidAccounting');
  }
  dispatch(id: string): boolean {
    return this.write(() => {
      const row = this.db.prepare('SELECT * FROM quota_attempt WHERE id=?').get(id) as Row | undefined;
      if (!row || !this.freeRow(row)) return false;
      return this.db.prepare("UPDATE quota_attempt SET state='dispatched' WHERE id=? AND state='reserved' AND expires>=?").run(id, this.time()).changes === 1;
    });
  }
  release(id: string): boolean {
    return this.write(() => {
      const row = this.db.prepare('SELECT * FROM quota_attempt WHERE id=?').get(id) as Row | undefined;
      if (!row || !this.freeRow(row)) return false;
      return this.releaseReserved(id);
    });
  }
  private releaseReserved(id: string): boolean {
    return this.db.prepare("UPDATE quota_attempt SET state='released',input=0,output=0,cost=0 WHERE id=? AND state='reserved'").run(id).changes === 1;
  }
  observe(id: string, observation: UsageObservation): boolean {
    return this.write(() => {
      const row = this.db.prepare('SELECT * FROM quota_attempt WHERE id=?').get(id) as Row | undefined;
      if (!row || !this.freeRow(row)) return false;
      const receipt = hash(JSON.stringify([observation.normal, observation.input ?? null, observation.output ?? null, observation.costMicros ?? null]));
      if (['settled', 'fault'].includes(row.state)) return row.receipt === receipt && row.state === 'settled';
      if (row.state !== 'dispatched' || this.time() > row.expires) return false;
      const input = observation.input === undefined ? undefined : integer(observation.input, this.policy.observationTokens);
      const output = observation.output === undefined ? undefined : integer(observation.output, this.policy.observationTokens);
      const cost = observation.costMicros === undefined ? undefined : integer(observation.costMicros, this.policy.observationCostMicros);
      const normal = observation.normal && input !== undefined && output !== undefined && cost === 0 && input <= row.reserve_input && output <= row.reserve_output;
      if (!normal && input === undefined && output === undefined && cost === undefined) return false;
      this.db.prepare(`UPDATE quota_attempt SET state=?,input=?,output=?,cost=?,receipt=? WHERE id=? AND state='dispatched'`).run(
        normal ? 'settled' : 'fault', normal ? input : Math.max(row.reserve_input, input ?? 0),
        normal ? output : Math.max(row.reserve_output, output ?? 0), normal ? 0 : Math.max(row.reserve_cost, cost ?? 0), receipt, id);
      return normal;
    });
  }
}
