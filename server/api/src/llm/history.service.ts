import { randomUUID } from 'node:crypto';
import { ConflictException, ForbiddenException, HttpException, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import { AuthStore, type SessionSnapshot } from '../auth/auth.store.js';
import { originForRequest, tokenFrom } from '../auth/auth.controller.js';
import type { Identity } from '../security/identity.js';
import { browserIdentity, type BrowserRequest, type BrowserScanLocalOrigin } from './browser-identity.js';
import { HISTORY, bytes, cleanText, hashValue, historyConflict, historyUnavailable, invalidHistoryRequest, isId, historyProjection, mutationInputHash,
  reportBinding, validateChatReply, type HistoryHead, type ReportBinding } from './history-contract.js';
import { PreparedContextCache, selectHistoryContext } from './history-context.js';
import { historyBodyParsed } from './history-ingress.js';
import { HistoryRuntime } from './history-runtime.js';
import { OpenRouterProvider, configError, type LlmProvider } from './openrouter-provider.js';
import { prepareHistory } from './prepared-request.js';
import { disclosure, type LlmPolicy } from './policy.js';
import type { LlmQuotaRuntime } from './quota-runtime.js';
import type { QuotaLedger } from './quota-ledger.js';
import { quotaUnavailable, type Vector } from './quota-policy.js';
import type { ReportContext, ReportReader } from './report-context.js';
import { exact } from './response.js';
import type { IncomingMessage } from 'node:http';
import type { ChatDelivery } from './history-delivery.js';

type Runtime = { policy(): LlmPolicy | null; provider(): LlmProvider };
type Access = { request: BrowserRequest; identity: Identity; session: SessionSnapshot };
export type HistoryResult = { value: unknown; write(action: () => void): void; delivery?: ChatDelivery; release?(): void };
const chatPolicy = (policy: LlmPolicy) => hashValue([policy.version, HISTORY.version, 'question-history-decisions-retained-no-output-cache']);
const stopped = (): never => { throw new ConflictException({ errorCode: 'LLM_REQUEST_ABORTED' }); };

export class HistoryService {
  readonly runtime = new HistoryRuntime();
  readonly cache = new PreparedContextCache();
  constructor(private readonly auth: AuthStore, private readonly reports: ReportReader, private readonly providerRuntime: Runtime,
    private readonly quotas: LlmQuotaRuntime, private readonly acquire: (owner: string) => () => void,
    private readonly localOrigin: BrowserScanLocalOrigin = 'http://127.0.0.1:8080') {}
  close() { this.runtime.close(); this.cache.clear(); }
  private access(request: BrowserRequest, mutation = false): Access {
    const base = browserIdentity(this.auth, request, false, this.localOrigin);
    if (mutation) {
      originForRequest(request);
      if (!historyBodyParsed(request as IncomingMessage & BrowserRequest)) return invalidHistoryRequest();
    }
    const session = this.auth.sessionForToken(tokenFrom(request) ?? '');
    if (!session || session.subject !== base.subject) throw new UnauthorizedException({ errorCode: 'UNAUTHORIZED' });
    return { request, session, identity: { subject: base.subject, scope: [...base.scope, 'scan:read'] } };
  }
  private guard<T>(access: Access, action: () => T, busyMs = 100): T {
    return this.auth.guardSession(access.session, () => {
      const current = browserIdentity(this.auth, access.request, false, this.localOrigin);
      if (current.subject !== access.identity.subject) throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
      return action();
    }, Math.min(busyMs, HISTORY.busyMs));
  }
  private current(access: Access, report: ReportBinding, policy?: LlmPolicy | null, signal?: AbortSignal) {
    if (signal?.aborted) return stopped();
    if (policy !== undefined) {
      const freshPolicy = this.providerRuntime.policy();
      if ((freshPolicy?.version ?? null) !== (policy?.version ?? null) || !!freshPolicy?.freeOnly !== !!policy?.freeOnly)
        throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
    }
    const fresh = this.reports.read(access.identity, report.scanId, HISTORY.busyMs);
    if (!Object.entries(reportBinding(fresh)).every(([key, value]) => (report as Record<string, unknown>)[key] === value))
      throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
  }
  private result(access: Access, report: ReportContext, head: HistoryHead, value: unknown, policy?: LlmPolicy | null, signal?: AbortSignal): HistoryResult {
    if (bytes(value) > HISTORY.scopeBytes) return historyUnavailable();
    return { value, write: action => this.guard(access, () => {
      this.current(access, report, policy, signal);
      this.runtime.store().guardHead(access.identity.subject, report.scanId, head.epoch, head.revision, action);
    }) };
  }
  read(request: BrowserRequest, scanId: string): HistoryResult {
    const access = this.access(request);
    return this.guard(access, () => {
      const report = this.reports.read(access.identity, scanId, HISTORY.busyMs), head = this.runtime.store().snapshot(access.identity.subject, scanId);
      return this.result(access, report, head, historyProjection(head, reportBinding(report)));
    });
  }
  context(request: BrowserRequest, scanId: string): HistoryResult {
    const access = this.access(request);
    return this.guard(access, () => {
      const report = this.reports.read(access.identity, scanId, HISTORY.busyMs), head = this.runtime.store().snapshot(access.identity.subject, scanId);
      const policy = this.providerRuntime.policy();
      return this.result(access, report, head, { ...reportBinding(report), epoch: head.epoch, revision: head.revision,
        enabled: !!policy?.freeOnly, policyVersion: policy?.freeOnly ? chatPolicy(policy) : null,
        disclosure: policy?.freeOnly ? { ...disclosure(policy), sentData: 'Cleaned question, all user history/accepted decisions and selected findings with complete coverage.',
          localRetention: 'Durable owner+scan history until separately authorized operator lifecycle; capacity can refuse; context cache only, not output cache.' } : null,
        limits: { questionBytes: HISTORY.questionBytes, bodyBytes: HISTORY.bodyBytes }, deliveryMode: 'completed-response', pending: !!head.pending,
        ...(report.profile ? { findingCount: report.findingCount, findingCounts: report.findingCounts,
          identifierCounts: report.identifierCounts, coverage: report.coverage } : {}) }, policy);
    });
  }
  usage(request: BrowserRequest, scanId: string): HistoryResult {
    const access = this.access(request);
    return this.guard(access, () => {
      const report = this.reports.read(access.identity, scanId, HISTORY.busyMs), head = this.runtime.store().snapshot(access.identity.subject, scanId);
      let usage: unknown;
      try { usage = { available: true, ...this.quotas.ledger().snapshot(access.identity.subject, scanId) }; }
      catch { usage = { available: false, admission: { status: 'unavailable' } }; }
      return this.result(access, report, head, { ...reportBinding(report), ...usage as Record<string, unknown> });
    });
  }
  private expected(body: Record<string, unknown>) {
    if (!isId(body.epoch) || !isId(body.mutationId) || !Number.isSafeInteger(body.revision) || (body.revision as number) < 0 ||
      typeof body.reportVersion !== 'string' || !/^[a-f0-9]{64}$/.test(body.reportVersion)) return invalidHistoryRequest();
    return { epoch: body.epoch, revision: body.revision as number, mutationId: body.mutationId };
  }
  decision(request: BrowserRequest, scanId: string, body: unknown): HistoryResult {
    const access = this.access(request, true);
    if (!exact(body, ['epoch', 'revision', 'mutationId', 'reportVersion', 'text', 'findingIds'])) return invalidHistoryRequest();
    const expected = this.expected(body), text = cleanText(body.text);
    if (!Array.isArray(body.findingIds) || body.findingIds.length > HISTORY.citations ||
      new Set(body.findingIds).size !== body.findingIds.length || body.findingIds.some(id => typeof id !== 'string')) return invalidHistoryRequest();
    const findingIds = body.findingIds as string[];
    return this.guard(access, () => {
      const report = this.reports.read(access.identity, scanId, HISTORY.busyMs);
      if (body.reportVersion !== report.reportVersion) throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
      const store = this.runtime.store(), duplicate = store.duplicate(access.identity.subject, scanId, expected.mutationId, (entry, head) =>
              head.epoch === expected.epoch && 'text' in entry && entry.text === text && entry.report.reportVersion === body.reportVersion &&
              hashValue(entry.sources.map(s => s.finding.findingId)) === hashValue(findingIds));
      if (duplicate) return this.result(access, report, store.snapshot(access.identity.subject, scanId), duplicate);
      const sources = findingIds.map(id => {
        const finding = report.findings.find(f => f.findingId === id);
        if (!finding) return invalidHistoryRequest();
        const source = { ...reportBinding(report), finding };
        if (bytes(source) > HISTORY.citationBytes) return invalidHistoryRequest(); return source;
      });
      const head = store.decision(access.identity.subject, scanId, expected.epoch, expected.revision,
        { id: randomUUID(), mutationId: expected.mutationId, kind: 'user-decision', text, report: reportBinding(report), sources });
      return this.result(access, report, head, historyProjection(head, reportBinding(report)));
    });
  }
  async generate(request: BrowserRequest, scanId: string, body: unknown, signal: AbortSignal, representation: 'json' | 'ndjson' = 'json'): Promise<HistoryResult> {
    const access = this.access(request, true);
    if (!exact(body, ['epoch', 'revision', 'mutationId', 'reportVersion', 'question', 'consent'])) return invalidHistoryRequest();
    const expected = this.expected(body), question = cleanText(body.question);
    if (!exact(body.consent, ['accepted', 'policyVersion']) || body.consent.accepted !== true)
      throw new ForbiddenException({ errorCode: 'LLM_CONSENT_REQUIRED' });
    const report = this.guard(access, () => this.reports.read(access.identity, scanId, HISTORY.busyMs));
    if (body.reportVersion !== report.reportVersion) throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
    const policy = this.providerRuntime.policy(); if (!policy?.freeOnly) throw configError();
    if (body.consent.policyVersion !== chatPolicy(policy)) throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
    const inputHash = mutationInputHash(scanId, { ...expected, reportVersion: report.reportVersion }, question, chatPolicy(policy));
    const store = this.guard(access, () => this.runtime.store());
    const duplicate = this.guard(access, () => store.duplicate(access.identity.subject, scanId, expected.mutationId, (entry, head) =>
      head.epoch === expected.epoch && 'question' in entry && entry.inputHash === inputHash && entry.consentPolicyVersion === chatPolicy(policy)));
    if (duplicate) return { ...this.result(access, report, store.snapshot(access.identity.subject, scanId), duplicate, policy, signal),
      delivery: { ...reportBinding(report), epoch: duplicate.epoch, revision: duplicate.revision, mutationId: expected.mutationId,
        turnId: duplicate.id, outcome: 'duplicate', state: duplicate.state } };
    const head = this.guard(access, () => {
      this.current(access, report, policy, signal);
      const head = store.snapshot(access.identity.subject, scanId);
      if (head.epoch !== expected.epoch || head.revision !== expected.revision || head.pending) return historyConflict(); return head;
    });
    const releaseCapacity = this.acquire(access.identity.subject);
    let transferred = false, released = false;
    const release = () => { if (!released) { released = true; releaseCapacity(); } };
    const controller = new AbortController(), abort = () => controller.abort();
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) controller.abort();
    const deadline = setTimeout(abort, policy.timeoutMs);
    let ledger: QuotaLedger | undefined, reservation: string | undefined, turnId: string | undefined;
        let observation: Vector | undefined;
        let admitted: { epoch: string; revision: number; requestHash: string; reservation: string } | undefined;
    try {
      if (!report.findings.length) throw new ConflictException({ errorCode: 'LLM_NO_EVIDENCE' });
      ledger = this.quotas.ledger();
      const selected = selectHistoryContext(report, head, question, policy, ledger.policy.requestInput);
      const key = hashValue([access.identity.subject, access.session, store.incarnation, reportBinding(report),
        head.epoch, head.revision, hashValue([head.turns, head.decisions]), policy.model, policy.providers, policy.version, chatPolicy(policy),
        HISTORY.version, question, selected.context.omission.selectedFindingIds]);
      const context = this.guard(access, () => {
        this.current(access, report, policy, controller.signal);
        const fresh = store.snapshot(access.identity.subject, scanId);
        if (fresh.epoch !== head.epoch || fresh.revision !== head.revision) return historyConflict();
        return this.cache.get(key, selected.context);
      });
      const prepared = prepareHistory(context, policy);
      if (prepared.reserve.input > ledger.policy.requestInput) throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' });
      const provider = this.providerRuntime.provider();
      if (!(provider instanceof OpenRouterProvider)) throw configError();
      turnId = randomUUID(); const id = turnId;
      const pending = this.guard(access, () => {
        this.current(access, report, policy, controller.signal);
        return store.begin(access.identity.subject, scanId, expected.epoch, expected.revision,
          { id, mutationId: expected.mutationId, state: 'pending', question, report: reportBinding(report), createdAt: Date.now(),
            inputHash, consentPolicyVersion: chatPolicy(policy), requestHash: prepared.hash },
          { id, sessionId: access.session.sessionId, generation: access.session.generation, accessIncarnation: access.session.accessIncarnation,
            policyVersion: chatPolicy(policy), deadline: Date.now() + 40000, requestHash: prepared.hash });
      });
      const boundLedger = ledger;
      reservation = this.guard(access, () => {
        this.current(access, report, policy, controller.signal);
        return store.guardPending(access.identity.subject, scanId, pending.epoch, pending.revision, id, () => boundLedger.withBusyTimeout(Math.min(HISTORY.busyMs, boundLedger.policy.busyMs), () => boundLedger.reserve({
          subject: access.identity.subject, scanId, reportVersion: report.reportVersion, policyVersion: policy.version, requestHash: prepared.hash }, prepared.reserve)));
      }, ledger.policy.busyMs);
      store.associate(access.identity.subject, scanId, pending.epoch, pending.revision, id, reservation);
      const boundReservation = reservation;
      admitted = { epoch: pending.epoch, revision: pending.revision, requestHash: prepared.hash, reservation: boundReservation };
      const raw = await provider.generateGuarded(prepared, policy, controller.signal, {
        policy: ledger.policy, observe: usage => {
          // Accounting is bound to original attempt, not current publication authority.
          if (!boundLedger.observe(boundReservation, usage)) throw quotaUnavailable();
          observation = { input: usage.input!, output: usage.output!, costMicros: usage.costMicros! };
        },
      }, send => this.guard(access, () => {
        this.current(access, report, policy, controller.signal);
        store.guardPending(access.identity.subject, scanId, pending.epoch, pending.revision, id, current => {
          const p = current.pending!;
          if (p.sessionId !== access.session.sessionId || p.generation !== access.session.generation ||
            p.accessIncarnation !== access.session.accessIncarnation || p.requestHash !== prepared.hash || p.reservation !== boundReservation ||
            p.policyVersion !== chatPolicy(policy)) return historyConflict();
          if (!boundLedger.withBusyTimeout(Math.min(HISTORY.busyMs, boundLedger.policy.busyMs), () => boundLedger.dispatch(boundReservation))) throw quotaUnavailable();
          send();
        });
      }, boundLedger.policy.busyMs));
      if (!observation) throw quotaUnavailable();
      const reply = validateChatReply(raw, context.report);
      const completed = this.guard(access, () => {
        this.current(access, report, policy, controller.signal);
        return store.finish(access.identity.subject, scanId, pending.epoch, pending.revision, id, reply);
      }, boundLedger.policy.busyMs);
      const usage = { ...observation, source: 'server-validated-provider-reported-not-invoice' as const };
      const result = this.result(access, report, completed, { ...reportBinding(report), epoch: completed.epoch, revision: completed.revision,
        turnId: id, deliveryMode: 'completed-response', reply, usage,
        ...(report.profile ? { findingCount: report.findingCount, findingCounts: report.findingCounts,
          identifierCounts: report.identifierCounts, coverage: report.coverage, contextSelection: context.omission } : {}) }, policy, signal);
      // Observation already persisted against the exact attempt; reply already committed. No receipt inference or auth boolean.
      const delivery: ChatDelivery = { ...reportBinding(report), epoch: completed.epoch, revision: completed.revision,
        mutationId: expected.mutationId, turnId: id, outcome: 'completed', reply, usage };
      transferred = true;
      return { ...result, delivery, release };
    } catch (error) {
      // Only this invocation's successful durable observe can establish a receipt; never inspect exception metadata/counters.
      if (representation === 'ndjson' && admitted && turnId && !controller.signal.aborted) {
        try {
          const id = turnId, attempt = admitted;
          const failed = this.guard(access, () => {
            this.current(access, report, policy, controller.signal);
            return store.guardPending(access.identity.subject, scanId, attempt.epoch, attempt.revision, id, current => {
              const p = current.pending!;
              if (p.sessionId !== access.session.sessionId || p.generation !== access.session.generation ||
                p.accessIncarnation !== access.session.accessIncarnation || p.requestHash !== attempt.requestHash ||
                p.reservation !== attempt.reservation || p.policyVersion !== chatPolicy(policy)) return historyConflict();
              if (!store.fail(access.identity.subject, scanId, attempt.epoch, id, 'failed')) return historyConflict();
              const failed = store.snapshot(access.identity.subject, scanId), turn = failed.turns.find(t => t.id === id);
              if (failed.epoch !== attempt.epoch || failed.revision !== attempt.revision + 1 || failed.pending ||
                !turn || turn.state !== 'failed' || turn.reply || turn.mutationId !== expected.mutationId ||
                turn.inputHash !== inputHash || turn.requestHash !== attempt.requestHash) return historyConflict();
              return failed;
            });
          });
          const binding = { ...reportBinding(report), epoch: failed.epoch, revision: failed.revision,
            mutationId: expected.mutationId, turnId: id, outcome: 'failed' as const };
          const delivery: ChatDelivery = observation
            ? Object.freeze({ ...binding, usage: Object.freeze({ ...observation, source: 'server-validated-provider-reported-not-invoice' as const }) })
            : Object.freeze({ ...binding, receipt: 'unavailable' as const });
          const result = this.result(access, report, failed, { errorCode: 'LLM_UNAVAILABLE' }, policy, signal);
          transferred = true;
          return { ...result, delivery, release };
        } catch { /* No proven current failed head: retain the safe exception path, never synthesize a delivery. */ }
      }
      if (turnId) { try { store.fail(access.identity.subject, scanId, expected.epoch, turnId, controller.signal.aborted ? 'cancelled' : 'failed'); } catch { /* Saved state unavailable, never fake success. */ } }
      if (error instanceof HttpException) throw error;
      throw new ServiceUnavailableException({ errorCode: 'LLM_UNAVAILABLE' });
    } finally {
      if (ledger && reservation) { try { ledger.release(reservation); } catch { /* No proven refund. */ } }
      clearTimeout(deadline); signal.removeEventListener('abort', abort); controller.abort();
      if (!transferred) release();
    }
  }
}
