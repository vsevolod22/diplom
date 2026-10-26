import { BadRequestException, ConflictException, ForbiddenException, HttpException, Inject, Injectable, Optional, NotFoundException, ServiceUnavailableException } from '@nestjs/common';
import { AuthStore } from '../auth/auth.store.js';
import { HistoryService } from './history.service.js';
import { TranslationService } from './translation.service.js';
import { historyUnavailable } from './history-contract.js';
import type { Identity } from '../security/identity.js';
import { PUBLIC_LLM_REPORTS, ReportReader, type ReportContext } from './report-context.js';
import { policyFromEnvironment, disclosure, type LlmPolicy } from './policy.js';
import { productionProvider, configError, type LlmProvider } from './openrouter-provider.js';
import { exact, validateReply } from './response.js';
import { LlmQuotaRuntime } from './quota-runtime.js';
import { quotaUnavailable, type Vector } from './quota-policy.js';
import { prepareSummary } from './prepared-request.js';
import { BROWSER_SCAN_LOCAL_ORIGIN, type BrowserScanLocalOrigin } from './browser-identity.js';
import { selectSummaryReport } from './summary-context.js';
import type { QuotaLedger } from './quota-ledger.js';
import { publicCredentialStatus, publicReadiness } from './public-readiness.js';
import { PUBLIC_OPENROUTER_KEY_FILE } from './public-key-file.js';
import { abortDiagnostic, stoppedDiagnostic } from './provider-diagnostic.js';

@Injectable()
export class LlmRuntime {
  constructor(@Optional() @Inject(PUBLIC_LLM_REPORTS) private readonly publicReports = false) {}
  policy(env: NodeJS.ProcessEnv = process.env): LlmPolicy | null {
    const policy = policyFromEnvironment(env);
    return this.publicReports && !policy?.freeOnly ? null : policy;
  }
  provider(env: NodeJS.ProcessEnv = process.env): LlmProvider {
    if (this.publicReports && (env.OPENROUTER_API_KEY_FILE !== PUBLIC_OPENROUTER_KEY_FILE || env.OPENROUTER_API_KEY !== undefined))
      throw configError();
    return productionProvider(env);
  }
  credentialStatus() { return publicCredentialStatus(); }
}
@Injectable()
export class LlmService {
  private readonly active = new Set<string>();
  private historyService?: HistoryService;
  private translationService?: TranslationService;
  constructor(@Inject(ReportReader) private readonly reports: ReportReader, @Inject(LlmRuntime) private readonly runtime: LlmRuntime,
      @Inject(LlmQuotaRuntime) private readonly quotas: LlmQuotaRuntime, @Optional() @Inject(AuthStore) private readonly auth?: AuthStore,
      @Optional() @Inject(BROWSER_SCAN_LOCAL_ORIGIN) private readonly localOrigin: BrowserScanLocalOrigin = 'http://127.0.0.1:8080') {}
  history(): HistoryService {
    if (!this.auth) return historyUnavailable();
    return this.historyService ??= new HistoryService(this.auth, this.reports, this.runtime, this.quotas, owner => this.acquire(owner), this.localOrigin);
  }
  translation(): TranslationService {
    if (!this.auth || this.localOrigin !== 'http://127.0.0.1:8081') throw new NotFoundException({ errorCode: 'SCAN_NOT_FOUND' });
    return this.translationService ??= new TranslationService(this.auth, this.reports, this.runtime, this.quotas, owner => this.acquire(owner), this.localOrigin);
  }
  onModuleDestroy() { this.historyService?.close(); }
  private acquire(owner: string): () => void {
    if (this.active.size >= 8 || this.active.has(owner)) throw new HttpException({ errorCode: 'LLM_CAPACITY' }, 429);
    this.active.add(owner); return () => { this.active.delete(owner); };
  }
  context(identity: Identity, scanId: string) {
    const report = this.reports.read(identity, scanId);
    const policy = this.runtime.policy();
    return { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
      policyVersion: policy?.version ?? null, disclosure: policy ? disclosure(policy) : null, enabled: policy !== null,
      ...(report.profile ? { findingCount: report.findingCount, findingCounts: report.findingCounts,
        identifierCounts: report.identifierCounts, coverage: report.coverage } : {}) };
  }
  readiness(identity: Identity, scanId: string) {
    // Owner/report binding precedes even non-secret setup metadata. This route does
    // not need a history head, read a key, grant consent or contact the provider.
    const report = this.reports.read(identity, scanId);
    if (!report.profile) throw new NotFoundException();
    let quotaAvailable = false, historyAvailable = false;
    try { this.quotas.ledger().snapshot(identity.subject, scanId); quotaAvailable = true; } catch { /* No raw store diagnostics. */ }
    try { this.history().runtime.store(); historyAvailable = true; } catch { /* Never initialize missing stores. */ }
    return { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
      ...publicReadiness(this.runtime.policy(), this.runtime.credentialStatus(), quotaAvailable, historyAvailable) };
  }
  usage(identity: Identity, scanId: string) {
    const report = this.reports.read(identity, scanId);
    const binding = { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion };
    const policy = this.runtime.policy();
        const flags = { integrationEnabled: policy !== null, quotaEnabled: process.env.LLM_QUOTA_ENABLED === 'true' };
    try {
      const ledger = this.quotas.ledger();
      let reserve: Vector | undefined;
            // The exact current free producer is shared with generation. This read never
            // constructs a provider, inspects its key, grants consent or reserves tokens.
            if (policy?.freeOnly && report.findings.length > 0 && (report.profile ||
                report.findings.length <= policy.findings && Buffer.byteLength(JSON.stringify(report)) <= policy.requestBytes)) {
              try {
                const candidate = prepareSummary(selectSummaryReport(report, policy, ledger.policy.requestInput), policy).reserve;
                if (candidate.input <= ledger.policy.requestInput) reserve = candidate;
              } catch { /* Candidate cannot be established safely; counters are still useful. */ }
            }
            return { ...binding, ...flags, quotaEnabled: true, available: true, ...ledger.snapshot(identity.subject, scanId, reserve) };
    } catch { return { ...binding, ...flags, available: false, reason: flags.quotaEnabled ? 'unavailable' : 'disabled' }; }
  }
  async summary(authorize: () => Identity, scanId: string, body: unknown, signal: AbortSignal) {
    // Owner and explicit opt-in precede even provider/key configuration inspection.
    const identity = authorize();
    const report = this.reports.read(identity, scanId);
    if (!exact(body, ['reportVersion', 'consent'])) throw new BadRequestException({ errorCode: 'LLM_INVALID_REQUEST' });
    if (!exact(body.consent, ['accepted', 'policyVersion']) || body.consent.accepted !== true)
      throw new ForbiddenException({ errorCode: 'LLM_CONSENT_REQUIRED' });
    if (body.reportVersion !== report.reportVersion) throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
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
      return response;
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
