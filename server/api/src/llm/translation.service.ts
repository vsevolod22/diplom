import { BadRequestException, ConflictException, ForbiddenException, HttpException, NotFoundException, ServiceUnavailableException, UnauthorizedException } from '@nestjs/common';
import type { AuthStore, SessionSnapshot } from '../auth/auth.store.js';
import { abortDiagnostic, diagnose, stoppedDiagnostic } from './provider-diagnostic.js';
import { originForRequest, tokenFrom } from '../auth/auth.controller.js';
import type { Identity } from '../security/identity.js';
import { browserIdentity, type BrowserRequest, type BrowserScanLocalOrigin } from './browser-identity.js';
import { translationBodyParsed } from './translation-ingress.js';
import { OpenRouterProvider, configError, type LlmProvider } from './openrouter-provider.js';
import type { LlmPolicy } from './policy.js';
import { prepareTranslation } from './prepared-request.js';
import type { QuotaLedger } from './quota-ledger.js';
import { quotaUnavailable } from './quota-policy.js';
import type { LlmQuotaRuntime } from './quota-runtime.js';
import type { ReportReader } from './report-context.js';
import { exact } from './response.js';
import { TRANSLATION, translationBinding, translationDisclosure, translationEnabled, translationPolicy, translationQuery,
  translationRequest, validateTranslationReply, type TranslationSnapshot } from './translation-contract.js';

type Runtime = { policy(): LlmPolicy | null; provider(): LlmProvider };
type Access = { request: BrowserRequest; identity: Identity; session: SessionSnapshot };
export type TranslationResult = { value: unknown; write(action: () => void): void; release?(): void };

// An operation of LlmService, sharing its runtime, provider, quotas and capacity.
// No history store, second provider, output cache or persistent translation state.
export class TranslationService {
  constructor(private readonly auth: AuthStore, private readonly reports: ReportReader, private readonly runtime: Runtime,
    private readonly quotas: LlmQuotaRuntime, private readonly acquire: (owner: string) => () => void,
    private readonly localOrigin: BrowserScanLocalOrigin) {}
  private access(request: BrowserRequest, mutation = false): Access {
    if (this.localOrigin !== 'http://127.0.0.1:8081') throw new NotFoundException({ errorCode: 'SCAN_NOT_FOUND' });
    const identity = browserIdentity(this.auth, request, false, this.localOrigin);
    if (mutation) {
      originForRequest(request);
      if (!translationBodyParsed(request)) throw new BadRequestException({ errorCode: 'LLM_INVALID_REQUEST' });
    }
    const session = this.auth.sessionForToken(tokenFrom(request) ?? '');
    if (!session || session.subject !== identity.subject) throw new UnauthorizedException({ errorCode: 'UNAUTHORIZED' });
    return { request, session, identity: { ...identity, scope: [...identity.scope, 'scan:read'] } };
  }
  private guard<T>(access: Access, action: () => T): T {
    return this.auth.guardSession(access.session, () => {
      if (browserIdentity(this.auth, access.request, false, this.localOrigin).subject !== access.identity.subject)
        throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
      return action();
    }, TRANSLATION.busyMs);
  }
  private current<T>(access: Access, initial: TranslationSnapshot, policy: LlmPolicy | null, signal: AbortSignal | undefined,
    action: () => T): T {
    return this.guard(access, () => {
      if (signal?.aborted) {
        const error = new ConflictException({ errorCode: 'LLM_REQUEST_ABORTED' });
        stoppedDiagnostic(signal, error); throw error;
      }
      const fresh = this.runtime.policy();
      if ((fresh?.version ?? null) !== (policy?.version ?? null) || !!fresh?.freeOnly !== !!policy?.freeOnly)
        throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
      return this.reports.withTranslation(access.identity, initial.scanId, initial.findingId, initial.assessmentIndex, snapshot => {
        if (snapshot.reportVersion !== initial.reportVersion || snapshot.digest !== initial.digest || snapshot.platform !== initial.platform)
          throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
        if (snapshot.sourceVersion !== initial.sourceVersion) throw new ConflictException({ errorCode: 'LLM_STALE_SOURCE' });
        return action();
      });
    });
  }
  context(request: BrowserRequest, scanId: string, query: unknown): TranslationResult {
    const access = this.access(request), selection = translationQuery(query);
    const snapshot = this.guard(access, () => this.reports.readTranslation(access.identity, scanId, selection.findingId, selection.assessmentIndex));
    const policy = this.runtime.policy(), enabled = translationEnabled(policy);
    return { value: { ...translationBinding(snapshot), targetLanguage: 'ru', source: snapshot.source,
      enabled, policyVersion: enabled ? translationPolicy(policy!) : null, disclosure: enabled ? translationDisclosure(policy!) : null },
      write: action => this.current(access, snapshot, policy, undefined, action) };
  }
  async generate(request: BrowserRequest, scanId: string, body: unknown, signal: AbortSignal): Promise<TranslationResult> {
    const access = this.access(request, true), input = translationRequest(body);
    if (!exact(input.consent, ['accepted', 'policyVersion']) || input.consent.accepted !== true)
      throw new ForbiddenException({ errorCode: 'LLM_CONSENT_REQUIRED' });
    const snapshot = this.guard(access, () => this.reports.readTranslation(access.identity, scanId, input.findingId, input.assessmentIndex));
    if (input.reportVersion !== snapshot.reportVersion) throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
    if (input.sourceVersion !== snapshot.sourceVersion) throw new ConflictException({ errorCode: 'LLM_STALE_SOURCE' });
    const policy = this.runtime.policy();
    if (!translationEnabled(policy)) throw configError();
    if (input.consent.policyVersion !== translationPolicy(policy)) throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
    const releaseCapacity = this.acquire(access.identity.subject);
    let transferred = false, released = false;
    const release = () => { if (!released) { released = true; releaseCapacity(); } };
    const controller = new AbortController(), abort = () => abortDiagnostic(controller, 'caller_abort');
    signal.addEventListener('abort', abort, { once: true });
    if (signal.aborted) abort();
    const deadline = setTimeout(() => abortDiagnostic(controller, 'deadline'), policy.timeoutMs);
    let ledger: QuotaLedger | undefined, reservation: string | undefined;
    try {
      this.current(access, snapshot, policy, controller.signal, () => undefined);
      const prepared = prepareTranslation(snapshot.text, policy);
      ledger = this.quotas.ledger();
      if (prepared.reserve.input > ledger.policy.requestInput) throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' });
      const boundLedger = ledger;
      reservation = this.current(access, snapshot, policy, controller.signal, () => boundLedger.withBusyTimeout(
        Math.min(TRANSLATION.busyMs, boundLedger.policy.busyMs), () => boundLedger.reserve({ subject: access.identity.subject,
          scanId, reportVersion: snapshot.reportVersion, policyVersion: translationPolicy(policy), requestHash: prepared.hash }, prepared.reserve)));
      const boundReservation = reservation;
      const provider = this.runtime.provider();
      if (!(provider instanceof OpenRouterProvider)) throw configError();
      let observed = false, dispatched = false;
      const operation = provider.generateGuarded(prepared, policy, controller.signal, { policy: ledger.policy, observe: usage => {
        // A late receipt accounts against this attempt even after revocation/abort; it cannot publish or resend.
        if (!boundLedger.observe(boundReservation, usage)) throw quotaUnavailable();
        observed = true;
      } }, send => this.current(access, snapshot, policy, controller.signal, () => {
        if (dispatched || !boundLedger.withBusyTimeout(Math.min(TRANSLATION.busyMs, boundLedger.policy.busyMs),
          () => boundLedger.dispatch(boundReservation))) throw quotaUnavailable();
        dispatched = true;
        send();
      }));
      const raw = await operation;
      if (!observed || !dispatched) throw quotaUnavailable();
      const translation = validateTranslationReply(raw, snapshot.text);
      this.current(access, snapshot, policy, controller.signal, () => undefined);
      const value = { ...translationBinding(snapshot), source: snapshot.source, translation, machineTranslated: true as const,
        targetLanguage: 'ru' as const, model: policy.model, provider: 'OpenRouter' as const, generatedAt: new Date().toISOString() };
      if (Buffer.byteLength(JSON.stringify(value)) > policy.responseBytes)
        throw new ServiceUnavailableException({ errorCode: 'LLM_RESPONSE_LIMIT' });
      transferred = true;
      return { value, write: action => this.current(access, snapshot, policy, signal, action), release };
    } catch (error) {
      if (error instanceof HttpException) {
        const value = error.getResponse();
        if (value && typeof value === 'object' && 'errorCode' in value && value.errorCode === 'LLM_INVALID_RESPONSE')
          diagnose(error, 'content', 'invalid_content');
        throw error;
      }
      throw new ServiceUnavailableException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
    } finally {
      if (ledger && reservation) { try { ledger.release(reservation); } catch { /* Dispatched liability is never refunded. */ } }
      clearTimeout(deadline); signal.removeEventListener('abort', abort); controller.abort();
      if (!transferred) release();
    }
  }
}
