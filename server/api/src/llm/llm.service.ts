import { BadRequestException, ConflictException, ForbiddenException, HttpException, Inject, Injectable, Optional, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { AuthStore, type SessionSnapshot } from '../auth/auth.store.js';
import { tokenFrom } from '../auth/auth.controller.js';
import { HistoryService } from './history.service.js';
import { HistoryRuntime } from './history-runtime.js';
import { TranslationService } from './translation.service.js';
import { historyUnavailable } from './history-contract.js';
import type { Identity } from '../security/identity.js';
import { PUBLIC_LLM_REPORTS, ReportReader, type ReportContext } from './report-context.js';
import { CEILINGS, policyFromEnvironment, publicFreePolicy, type LlmPolicy } from './policy.js';
import { productionProvider, configError, type LlmProvider } from './openrouter-provider.js';
import { openRouterTransportForPolicy } from './openrouter-transport.js';
import { exact, validateReply } from './response.js';
import { LlmQuotaRuntime } from './quota-runtime.js';
import { quotaUnavailable } from './quota-policy.js';
import { BROWSER_SCAN_LOCAL_ORIGIN, browserIdentity, type BrowserRequest, type BrowserScanLocalOrigin } from './browser-identity.js';
import type { SummaryPublication } from './summary-result-cache.js';
import { SUMMARY_STORAGE } from './summary-record.js';
import { selectSummaryReport, selectPreparedSummary } from './summary-context.js';
import { requirePublicSummaryReport, supportsPublicSummary } from './summary-report-support.js';
import type { QuotaLedger } from './quota-ledger.js';
import { publicCredentialStatus, publicReadiness, openAiReadiness } from './public-readiness.js';
import { OpenAiRuntimeResolver, PROVIDER_RUNTIME_OPTIONS, openRouterRuntime, resolveProviderRuntime, type ProviderRuntimeOptions } from './provider-runtime.js';
import type { ProviderRuntimeSnapshot, RuntimeAttempt } from './provider-runtime-contract.js';
import type { SummaryResponse } from './summary-result-cache.js';
import { PUBLIC_OPENROUTER_KEY_FILE } from './public-key-file.js';
import { abortDiagnostic, diagnose, stoppedDiagnostic } from './provider-diagnostic.js';

@Injectable()
export class LlmRuntime {
  private readonly openAi: OpenAiRuntimeResolver;
    constructor(@Optional() @Inject(PUBLIC_LLM_REPORTS) private readonly publicReports = false,
      @Optional() @Inject(PROVIDER_RUNTIME_OPTIONS) options?: ProviderRuntimeOptions) { this.openAi = new OpenAiRuntimeResolver(options); }
    resolve(): ProviderRuntimeSnapshot | null {
      const selected = this.publicReports ? this.openAi.selected() : 'openrouter';
      if (selected === null) return null;
      if (selected === 'openai') return this.openAi.inspect().runtime;
      const policy = this.policy();
      return policy ? openRouterRuntime(policy, () => this.provider()) : null;
    }
    translationCompatible(): boolean { return !this.publicReports || this.openAi.translationCompatible(); }
    openAiReadiness(quotaAvailable: boolean, historyAvailable: boolean) {
      return this.publicReports && this.openAi.selected() === 'openai' ? openAiReadiness(this.openAi, quotaAvailable, historyAvailable) : null;
    }
  policy(env: NodeJS.ProcessEnv = process.env): LlmPolicy | null {
    const policy = policyFromEnvironment(env);
    if (!this.publicReports && policy && (policy.timeoutMs > CEILINGS.timeoutMs || policy.outputTokens > CEILINGS.outputTokens)) return null;
    return this.publicReports && !publicFreePolicy(policy) ? null : policy;
  }
  provider(env: NodeJS.ProcessEnv = process.env): LlmProvider {
    if (this.publicReports && (env.OPENROUTER_API_KEY_FILE !== PUBLIC_OPENROUTER_KEY_FILE || env.OPENROUTER_API_KEY !== undefined))
      throw configError();
    if (this.publicReports) {
      const policy = this.policy(env);
      if (!policy) throw configError();
      return productionProvider(env, openRouterTransportForPolicy(policy));
    }
    return productionProvider(env);
  }
  credentialStatus() { return publicCredentialStatus(); }
}
type SummaryAccess = { request: BrowserRequest; identity: Identity; session: SessionSnapshot };

@Injectable()
export class LlmService {
  private readonly active = new Set<string>();
  private historyService?: HistoryService;
  private translationService?: TranslationService;
  constructor(@Inject(ReportReader) private readonly reports: ReportReader, @Inject(LlmRuntime) private readonly runtime: LlmRuntime,
      @Inject(LlmQuotaRuntime) private readonly quotas: LlmQuotaRuntime, @Optional() @Inject(AuthStore) private readonly auth?: AuthStore,
      @Optional() @Inject(BROWSER_SCAN_LOCAL_ORIGIN) private readonly localOrigin: BrowserScanLocalOrigin = 'http://127.0.0.1:8080',
      @Optional() @Inject(HistoryRuntime) private readonly historyRuntime = new HistoryRuntime()) {}
  history(): HistoryService {
    if (!this.auth) return historyUnavailable();
    return this.historyService ??= new HistoryService(this.auth, this.reports, this.runtime, this.quotas, owner => this.acquire(owner), this.localOrigin, this.historyRuntime);
  }
  translation(): TranslationService {
    if (!this.auth || this.localOrigin !== 'http://127.0.0.1:8081') throw new NotFoundException({ errorCode: 'SCAN_NOT_FOUND' });
    return this.translationService ??= new TranslationService(this.auth, this.reports, this.runtime, this.quotas,
          owner => this.acquire(owner), this.localOrigin);
  }
  onModuleDestroy() { this.historyService?.close(); this.historyRuntime.close(); }
  // Retained controller seam: this selects the public durable path, not a RAM cache.
  summaryCacheEnabled() { return this.localOrigin === 'http://127.0.0.1:8081' && !!this.auth; }
  private summaryAccess(request: BrowserRequest): SummaryAccess {
    if (!this.summaryCacheEnabled()) throw new NotFoundException({ errorCode: 'SCAN_NOT_FOUND' });
    const identity = browserIdentity(this.auth!, request, false, this.localOrigin);
    const session = this.auth!.sessionForToken(tokenFrom(request) ?? '');
    if (!session || session.subject !== identity.subject) throw new ServiceUnavailableException({ errorCode: 'AUTH_UNAVAILABLE' });
    return { request, session, identity: { ...identity, scope: [...identity.scope, 'scan:read'] } };
  }
  private summaryIdentity(access: SummaryAccess, mutation = false): Identity {
    const identity = browserIdentity(this.auth!, access.request, mutation, this.localOrigin);
    if (identity.subject !== access.identity.subject) throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
    return { ...identity, scope: [...identity.scope, 'scan:read'] };
  }
  private withSummary<T>(access: SummaryAccess, scanId: string, action: (report: ReportContext, policy: ProviderRuntimeSnapshot | null) => T): T {
    return this.auth!.guardSession(access.session, () => {
      const identity = this.summaryIdentity(access);
      // Owner lookup and full current report precede policy disclosure or stored output access.
      return this.reports.withSummaryReport(identity, scanId, report => action(report, resolveProviderRuntime(this.runtime)));
    }, SUMMARY_STORAGE.busyMs);
  }
  private currentSummary(report: ReportContext, policy: ProviderRuntimeSnapshot, fresh: ReportContext, current: ProviderRuntimeSnapshot | null, signal?: AbortSignal) {
    if (signal?.aborted) throw new ConflictException({ errorCode: 'LLM_REQUEST_ABORTED' });
    if (fresh.reportVersion !== report.reportVersion || fresh.digest !== report.digest || fresh.platform !== report.platform)
      throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
    if (current?.version !== policy.version) throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
    if (!current?.durableSummary || current.provider !== policy.provider) throw configError();
  }
  private assertSummaryDeadline(expiresAt?: number): void {
    // Synchronous SQLite work can cross expiry before the timer gets a turn.
    if (expiresAt !== undefined && Date.now() >= expiresAt)
      throw diagnose(new ServiceUnavailableException({ errorCode: 'LLM_REQUEST_ABORTED' }), 'deadline', 'timeout');
  }
  private summaryPublication(access: SummaryAccess, report: ReportContext, policy: ProviderRuntimeSnapshot, value: SummaryPublication['value'],
    signal?: AbortSignal, expiresAt?: number): SummaryPublication {
    this.assertSummaryDeadline(expiresAt);
    const body = JSON.stringify(value);
    return { value: JSON.parse(body) as SummaryPublication['value'], write: action => this.withSummary(access, report.scanId, (fresh, current) => {
      this.currentSummary(report, policy, fresh, current, signal);
      // Re-read and validate at the final fence too: a replaced DB, corrupt row or
      // intervening summary replacement cannot publish a previously loaded copy.
      const stored = this.historyRuntime.summaryStore().readSummary(access.identity.subject, fresh, policy.summaryPolicy);
      if (!stored || JSON.stringify(stored) !== body) return historyUnavailable();
      // The durable re-read/validation can itself cross expiry. Keep the original
      // generation deadline through publication, independent of timer cleanup.
      this.assertSummaryDeadline(expiresAt);
      action();
    }) };
  }
  readSummary(request: BrowserRequest, scanId: string): SummaryPublication {
    const access = this.summaryAccess(request);
    return this.withSummary(access, scanId, (report, policy) => {
      const store = this.historyRuntime.summaryStore();
      if (!policy?.durableSummary) throw configError();
      const value = store.readSummary(access.identity.subject, report, policy.summaryPolicy);
      // Only absence of a matching record in a healthy, migrated store is missing.
      if (!value) throw new NotFoundException({ errorCode: 'LLM_SUMMARY_MISSING' });
      return this.summaryPublication(access, report, policy, value);
    });
  }
  async summaryForBrowser(request: BrowserRequest, scanId: string, body: unknown, signal: AbortSignal): Promise<SummaryPublication> {
    const access = this.summaryAccess(request);
    const generated = await this.generatePublicSummary(access, scanId, body, signal);
    return this.summaryPublication(access, generated.report, generated.policy, generated.value, signal, generated.expiresAt);
  }
  private async generatePublicSummary(access: SummaryAccess, scanId: string, body: unknown, signal: AbortSignal) {
    this.auth!.guardSession(access.session, () => this.summaryIdentity(access, true), SUMMARY_STORAGE.busyMs);
    const report = this.reports.read(access.identity, scanId, SUMMARY_STORAGE.busyMs);
    if (!exact(body, ['reportVersion', 'consent'])) throw new BadRequestException({ errorCode: 'LLM_INVALID_REQUEST' });
    if (!exact(body.consent, ['accepted', 'policyVersion']) || body.consent.accepted !== true)
      throw new ForbiddenException({ errorCode: 'LLM_CONSENT_REQUIRED' });
    if (body.reportVersion !== report.reportVersion) throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
    requirePublicSummaryReport(report);
    const policy = resolveProviderRuntime(this.runtime);
    if (!policy?.durableSummary) throw configError();
    if (body.consent.policyVersion !== policy.version) throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
    if (!report.findings.length) throw new ConflictException({ errorCode: 'LLM_NO_EVIDENCE' });
    const release = this.acquire(access.identity.subject), controller = new AbortController();
    const abort = () => abortDiagnostic(controller, 'caller_abort');
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const expiresAt = Date.now() + policy.timeoutMs;
    const deadline = setTimeout(() => abortDiagnostic(controller, 'deadline'), policy.timeoutMs);
    let attempt: RuntimeAttempt<SummaryResponse> | undefined;
    let releaseStorage: (() => void) | undefined;
    let dispatched = false;
    try {
      const { store, storageReservation } = this.withSummary(access, scanId, (fresh, current) => {
        this.currentSummary(report, policy, fresh, current, controller.signal);
        const store = this.historyRuntime.summaryStore();
        const storageReservation = store.reserveSummary(access.identity.subject, scanId, expiresAt);
        releaseStorage = () => store.releaseSummary(access.identity.subject, scanId, storageReservation);
        return { store, storageReservation };
      });
      const ledger = this.quotas.ledger();
      const selected = selectPreparedSummary(report, policy.findings, ledger.policy.requestInput, policy.prepareSummary);
      this.withSummary(access, scanId, (fresh, current) => {
        this.currentSummary(report, policy, fresh, current, controller.signal);
        store.guardSummaryReservation(access.identity.subject, scanId, storageReservation, () => {
          ledger.withBusyTimeout(Math.min(SUMMARY_STORAGE.busyMs, ledger.policy.busyMs), () => {
            attempt = selected.prepared.reserveAttempt(ledger, { subject: access.identity.subject, scanId,
              reportVersion: report.reportVersion, policyVersion: policy.providerPolicyVersion, requestHash: selected.prepared.hash });
          });
        });
      });
      if (!attempt) throw quotaUnavailable();
      let observed = false;
      const operation = attempt.generate(controller.signal, dispatchAndSend => this.withSummary(access, scanId, (fresh, current) => {
        this.currentSummary(report, policy, fresh, current, controller.signal);
        store.guardSummaryReservation(access.identity.subject, scanId, storageReservation, () =>
          ledger.withBusyTimeout(Math.min(SUMMARY_STORAGE.busyMs, ledger.policy.busyMs), dispatchAndSend));
      }), () => { observed = true; }, () => {
        // Called by the runtime after accounting dispatch, not during credential
        // access. Recheck after quota's synchronous busy wait, immediately at send.
        if (controller.signal.aborted) throw new ConflictException({ errorCode: 'LLM_REQUEST_ABORTED' });
        store.guardSummaryReservation(access.identity.subject, scanId, storageReservation, () => {});
        dispatched = true;
      });
      const stopped = new Promise<never>((_, reject) => {
        const stop = () => {
          const error = new ServiceUnavailableException({ errorCode: 'LLM_REQUEST_ABORTED' });
          stoppedDiagnostic(controller.signal, error); reject(error);
        };
        if (controller.signal.aborted) stop();
        else controller.signal.addEventListener('abort', stop, { once: true });
      });
      const result = await Promise.race([operation, stopped]);
      if (!observed) throw quotaUnavailable();
      this.withSummary(access, scanId, (fresh, current) => this.currentSummary(report, policy, fresh, current, controller.signal));
      const selection = selected.report.contextSelection;
      const value: SummaryResponse = selection ? { ...result, findingCount: report.findingCount, identifierCounts: report.identifierCounts,
        findingCounts: report.findingCounts, coverage: report.coverage, contextSelection: selection } : result;
      if (Buffer.byteLength(JSON.stringify(value)) > policy.responseBytes)
        throw new ServiceUnavailableException({ errorCode: 'LLM_RESPONSE_LIMIT' });
      const stored = this.withSummary(access, scanId, (fresh, current) => {
        this.currentSummary(report, policy, fresh, current, controller.signal);
        // Owner admission, deadline and auth/report fences stay held through the
        // token-bound FULL commit. HTTP publication follows a fresh durable read.
        return store.writeSummary(access.identity.subject, fresh, policy.summaryPolicy,
          JSON.parse(JSON.stringify(value)) as unknown, storageReservation);
      });
      // Commit/compaction may have finished after expiry while blocking timers.
      // Reject this operation only; its committed result remains available to GET.
      this.assertSummaryDeadline(expiresAt);
      return { value: stored, report, policy, expiresAt };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      throw new ServiceUnavailableException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
    } finally {
      // Pre-dispatch failure is safe to release. After dispatch, failure/unknown
      // retains the hold until explicit same-scope expiry acquisition; no refund.
      if (!dispatched) try { releaseStorage?.(); } catch { /* Leave the hold for explicit expiry acquisition. */ }
      try { attempt?.release(); } catch { /* Never infer a refund for a dispatched/unknown attempt. */ }
      clearTimeout(deadline); signal.removeEventListener('abort', abort); controller.abort(); release();
    }
  }
  private acquire(owner: string): () => void {
    if (this.active.size >= 8 || this.active.has(owner)) throw new HttpException({ errorCode: 'LLM_CAPACITY' }, 429);
    this.active.add(owner); return () => { this.active.delete(owner); };
  }
  context(identity: Identity, scanId: string) {
    const report = this.reports.read(identity, scanId);
    const supported = this.localOrigin !== 'http://127.0.0.1:8081' || supportsPublicSummary(report);
    const policy = supported ? resolveProviderRuntime(this.runtime) : null;
    return { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
      policyVersion: policy?.version ?? null, disclosure: policy ? policy.disclosure(report) : null, enabled: policy !== null,
      ...(!supported ? { unavailableReason: 'LLM_SUMMARY_UNSUPPORTED_REPORT' as const } : {}),
      ...(this.summaryCacheEnabled() ? { summaryResultRead: supported } : {}),
      ...(report.profile ? { findingCount: report.findingCount, findingCounts: report.findingCounts,
        identifierCounts: report.identifierCounts, coverage: report.coverage } : {}) };
  }
  readiness(identity: Identity, scanId: string) {
    // Owner/report binding precedes even non-secret setup metadata. This route does
    // not need a history head, read a key, grant consent or contact the provider.
    const report = this.reports.read(identity, scanId);
    if (this.localOrigin === 'http://127.0.0.1:8081') requirePublicSummaryReport(report);
    else if (!report.profile) throw new NotFoundException();
    let quotaAvailable = false, historyAvailable = false;
    try { this.quotas.ledger().snapshot(identity.subject, scanId); quotaAvailable = true; } catch { /* No raw store diagnostics. */ }
    try {
          this.history().runtime.assertHealthy();
          if (this.summaryCacheEnabled()) this.historyRuntime.summaryStore().requireSummaryReservationSchema();
          historyAvailable = true;
        } catch { /* Never initialize or migrate missing stores. */ }
    return { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
      ...(this.runtime.openAiReadiness?.(quotaAvailable, historyAvailable) ?? publicReadiness(
              resolveProviderRuntime(this.runtime)?.provider === 'OpenRouter' ? this.runtime.policy() : null,
              this.runtime.credentialStatus(), quotaAvailable, historyAvailable)) };
  }
  usage(identity: Identity, scanId: string) {
    const report = this.reports.read(identity, scanId);
    const binding = { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion };
    const policy = resolveProviderRuntime(this.runtime);
        const flags = { integrationEnabled: policy !== null, quotaEnabled: process.env.LLM_QUOTA_ENABLED === 'true' };
    try {
      const ledger = this.quotas.ledger();
      let snapshot = ledger.snapshot(identity.subject, scanId);
      // Exact producer, no provider/key/reservation. Unknown candidate is not fits.
      if (policy?.chatEnabled && report.findings.length > 0) {
        try {
          const { prepared } = selectPreparedSummary(report, policy.findings, ledger.policy.requestInput, policy.prepareSummary);
          snapshot = prepared.snapshot(ledger, { subject: identity.subject, scanId, reportVersion: report.reportVersion,
            policyVersion: policy.providerPolicyVersion, requestHash: prepared.hash });
        } catch { /* Counters remain useful without an admissible exact candidate. */ }
      }
      return { ...binding, ...flags, quotaEnabled: true, available: true, ...snapshot,
              ...(policy?.provider === 'OpenAI' ? { monetaryLimit: snapshot.monetaryLimit ?? 'capped' } : {}) };
    } catch { return { ...binding, ...flags, available: false, reason: flags.quotaEnabled ? 'unavailable' : 'disabled' }; }
  }
  async summary(authorize: () => Identity, scanId: string, body: unknown, signal: AbortSignal) {
    return (await this.generateSummary(authorize, scanId, body, signal)).value;
  }
  private async generateSummary(authorize: () => Identity, scanId: string, body: unknown, signal: AbortSignal,
    beforeProvider?: (report: ReportContext, policy: LlmPolicy) => void) {
    // Owner and explicit opt-in precede even provider/key configuration inspection.
    const identity = authorize();
    const report = this.reports.read(identity, scanId);
    if (!exact(body, ['reportVersion', 'consent'])) throw new BadRequestException({ errorCode: 'LLM_INVALID_REQUEST' });
    if (!exact(body.consent, ['accepted', 'policyVersion']) || body.consent.accepted !== true)
      throw new ForbiddenException({ errorCode: 'LLM_CONSENT_REQUIRED' });
    if (body.reportVersion !== report.reportVersion) throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
    // Owner, mutation headers and consent checks remain first. An unsupported
    // owned report is not a missing scan and cannot enter public generation.
    if (this.localOrigin === 'http://127.0.0.1:8081') requirePublicSummaryReport(report);
    const policy = this.runtime.policy();
    if (!policy) throw configError();
    if (body.consent.policyVersion !== policy.version) throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
    if (!report.profile && (report.findings.length > policy.findings || Buffer.byteLength(JSON.stringify(report)) > policy.requestBytes))
      throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' });
    const releaseCapacity = this.acquire(identity.subject);
    const controller = new AbortController();
    const abort = () => abortDiagnostic(controller, 'caller_abort');
    signal.addEventListener('abort', abort, { once: true });
    const deadline = setTimeout(() => abortDiagnostic(controller, 'deadline'), policy.timeoutMs);
    let ledger: QuotaLedger | undefined;
    let reservation: string | undefined;
    let sentReport = report;
    try {
      this.current(authorize, identity, report, policy, signal);
      // Every published hypothesis requires a real finding citation. An empty set
      // cannot support a reply; refuse locally, not after a paid/impossible request.
      if (!report.findings.length) throw new ConflictException({ errorCode: 'LLM_NO_EVIDENCE' });
      // Browser persistence preflight covers both public and legacy reports after
      // consent/current-report checks, before provider/key access or quota reservation.
      beforeProvider?.(report, policy);
      const provider = this.runtime.provider();
      if (signal.aborted) {
        const error = new ConflictException({ errorCode: 'LLM_REQUEST_ABORTED' });
        stoppedDiagnostic(signal, error); throw error;
      }
      const stopped = new Promise<never>((_, reject) => controller.signal.addEventListener('abort', () => {
        const error = new ServiceUnavailableException({ errorCode: 'LLM_REQUEST_ABORTED' });
        stoppedDiagnostic(controller.signal, error); reject(error);
      }, { once: true }));
      // Admission can throw before Promise.race attaches its rejection handler.
      void stopped.catch(() => {});
      let operation: Promise<unknown>;
      // Only the actual free-only production adapter opts into this narrow seam.
      // Three-argument fake providers and the separately configured legacy path
      // retain their existing contract; neither is evidence of quota acceptance.
      if (policy.freeOnly && provider.prepare && provider.summarizePrepared) {
        ledger = this.quotas.ledger();
        const selected = selectSummaryReport(report, policy, ledger.policy.requestInput);
        sentReport = selected;
        const prepared = provider.prepare(selected, policy);
        reservation = ledger.reserve({ subject: identity.subject, scanId, reportVersion: report.reportVersion,
          policyVersion: policy.version, requestHash: prepared.hash }, prepared.reserve);
        this.current(authorize, identity, report, policy, controller.signal);
        if (!ledger.dispatch(reservation)) throw quotaUnavailable();
        const boundLedger = ledger, boundReservation = reservation;
        let observed = false;
        operation = provider.summarizePrepared(prepared, policy, controller.signal, {
          policy: ledger.policy,
          observe: observation => {
            // Deliberately independent of current auth/publication and AbortSignal:
            // a late bound receipt may account once, never publish or resend.
            if (!boundLedger.observe(boundReservation, observation)) throw quotaUnavailable();
            observed = true;
          },
        }).then(value => { if (!observed) throw quotaUnavailable(); return value; });
      } else operation = provider.summarize(report, policy, controller.signal);
      const reply = await Promise.race([operation, stopped]);
      this.current(authorize, identity, report, policy, signal);
      const result = validateReply(reply, sentReport, policy.freeOnly);
            const selection = sentReport.contextSelection;
            const response = selection ? { ...result, findingCount: report.findingCount, identifierCounts: report.identifierCounts,
              findingCounts: report.findingCounts, coverage: report.coverage, contextSelection: selection } : result;
      if (Buffer.byteLength(JSON.stringify(response)) > policy.responseBytes)
        throw new ServiceUnavailableException({ errorCode: 'LLM_RESPONSE_LIMIT' });
      return { value: response, report, policy };
    } catch (error) {
      if (error instanceof HttpException) throw error;
      // Do not log/echo provider bodies, raw SQLite diagnostics, cookies or the key.
      throw new ServiceUnavailableException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
    } finally {
      // A dispatched/settled/fault attempt cannot be refunded by this release CAS.
      if (ledger && reservation) { try { ledger.release(reservation); } catch { /* Durable liability remains; never fabricate a refund. */ } }
      clearTimeout(deadline); signal.removeEventListener('abort', abort); controller.abort(); releaseCapacity();
    }
  }
  private current(authorize: () => Identity, initial: Identity, report: ReportContext, policy: LlmPolicy, signal: AbortSignal) {
    if (signal.aborted) {
      const error = new ConflictException({ errorCode: 'LLM_REQUEST_ABORTED' });
      stoppedDiagnostic(signal, error); throw error;
    }
    const currentIdentity = authorize();
    if (currentIdentity.subject !== initial.subject || !currentIdentity.scope.includes('scan:read'))
      throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
    if (this.runtime.policy()?.version !== policy.version) throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
    if (this.reports.read(currentIdentity, report.scanId).reportVersion !== report.reportVersion)
      throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
  }
}
