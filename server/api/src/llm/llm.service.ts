import { BadRequestException, ConflictException, ForbiddenException, HttpException, Inject, Injectable, ServiceUnavailableException } from '@nestjs/common';
import type { Identity } from '../security/identity.js';
import { ReportReader, type ReportContext } from './report-context.js';
import { policyFromEnvironment, disclosure, type LlmPolicy } from './policy.js';
import { productionProvider, configError, type LlmProvider } from './openrouter-provider.js';
import { exact, validateReply } from './response.js';

@Injectable()
export class LlmRuntime {
  policy(): LlmPolicy | null { return policyFromEnvironment(); }
  provider(): LlmProvider { return productionProvider(); }
}
@Injectable()
export class LlmService {
  private readonly active = new Set<string>();
  constructor(@Inject(ReportReader) private readonly reports: ReportReader, @Inject(LlmRuntime) private readonly runtime: LlmRuntime) {}
  context(identity: Identity, scanId: string) {
    const report = this.reports.read(identity, scanId);
    const policy = this.runtime.policy();
    return { scanId: report.scanId, digest: report.digest, platform: report.platform, reportVersion: report.reportVersion,
      policyVersion: policy?.version ?? null, disclosure: policy ? disclosure(policy) : null, enabled: policy !== null };
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
    if (report.findings.length > policy.findings || Buffer.byteLength(JSON.stringify(report)) > policy.requestBytes)
      throw new ConflictException({ errorCode: 'LLM_CONTEXT_LIMIT' });
    if (this.active.size >= 8 || this.active.has(identity.subject))
      throw new HttpException({ errorCode: 'LLM_CAPACITY' }, 429);
    this.active.add(identity.subject);
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal.addEventListener('abort', abort, { once: true });
    const deadline = setTimeout(abort, policy.timeoutMs);
    try {
      this.current(authorize, identity, report, policy, signal);
      // Every published hypothesis requires a real finding citation. An empty set
      // cannot support a reply; refuse locally, not after a paid/impossible request.
      if (!report.findings.length) throw new ConflictException({ errorCode: 'LLM_NO_EVIDENCE' });
      const provider = this.runtime.provider();
      if (signal.aborted) throw new ConflictException({ errorCode: 'LLM_REQUEST_ABORTED' });
      const stopped = new Promise<never>((_, reject) => controller.signal.addEventListener('abort', () =>
        reject(new ServiceUnavailableException({ errorCode: 'LLM_REQUEST_ABORTED' })), { once: true }));
      const reply = await Promise.race([provider.summarize(report, policy, controller.signal), stopped]);
      this.current(authorize, identity, report, policy, signal);
      const result = validateReply(reply, report);
      if (Buffer.byteLength(JSON.stringify(result)) > policy.responseBytes)
        throw new ServiceUnavailableException({ errorCode: 'LLM_RESPONSE_LIMIT' });
      return result;
    } catch (error) {
      if (error instanceof HttpException) throw error;
      // Do not log/echo provider bodies, raw SQLite diagnostics, cookies or the key.
      throw new ServiceUnavailableException({ errorCode: 'LLM_PROVIDER_UNAVAILABLE' });
    } finally {
      clearTimeout(deadline); signal.removeEventListener('abort', abort); controller.abort(); this.active.delete(identity.subject);
    }
  }
  private current(authorize: () => Identity, initial: Identity, report: ReportContext, policy: LlmPolicy, signal: AbortSignal) {
    if (signal.aborted) throw new ConflictException({ errorCode: 'LLM_REQUEST_ABORTED' });
    const currentIdentity = authorize();
    if (currentIdentity.subject !== initial.subject || !currentIdentity.scope.includes('scan:read'))
      throw new ForbiddenException({ errorCode: 'SCAN_ACCESS_DENIED' });
    if (this.runtime.policy()?.version !== policy.version) throw new ConflictException({ errorCode: 'LLM_STALE_POLICY' });
    if (this.reports.read(currentIdentity, report.scanId).reportVersion !== report.reportVersion)
      throw new ConflictException({ errorCode: 'LLM_STALE_REPORT' });
  }
}
