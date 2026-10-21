import { Module } from '@nestjs/common';
import type { NestExpressApplication } from '@nestjs/platform-express';
import { AuthModule } from '../auth/auth.module.js';
import { LedgerModule } from '../ledger/ledger.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { SecurityModule } from '../security/security.module.js';
import { OciModule } from './oci.module.js';
import { OciResolver } from './oci-resolver.js';
import { inspectPublicImage } from './public-image-archive.js';
import { ScansController } from '../scans/scans.controller.js';
import { BrowserScansController } from '../scans/browser-scans.controller.js';
import { ScansService } from '../scans/scans.service.js';
import { PUBLIC_IMAGE_INSPECTOR, PublicImageScansService, type PublicImageInspector } from '../scans/public-image-scans.service.js';
import { localDbTrustAnchorFromEnv } from '../worker/vuln-db-trust.js';
import { BROWSER_SCAN_LOCAL_ORIGIN, BrowserIdentity } from '../llm/browser-identity.js';
import { LlmController } from '../llm/llm.controller.js';
import { LlmRuntime, LlmService } from '../llm/llm.service.js';
import { PUBLIC_LLM_REPORTS, ReportReader } from '../llm/report-context.js';
import { LlmQuotaRuntime } from '../llm/quota-runtime.js';
import { llmExceptionProvider } from '../llm/llm-exception.filter.js';
import { registerHistoryIngress } from '../llm/history-ingress.js';

// Image-only public Docker Hub profile. No default ScansModule/LlmModule imports:
// those would create another, restricted ScansService. Runtime/host are not exposed here.
@Module({ imports: [AuthModule, LedgerModule, SecurityModule, OciModule],
  controllers: [ScansController, BrowserScansController, LlmController],
  providers: [BrowserIdentity, ReportReader, LlmRuntime, LlmService, LlmQuotaRuntime, llmExceptionProvider,
      { provide: PUBLIC_LLM_REPORTS, useValue: true }, { provide: BROWSER_SCAN_LOCAL_ORIGIN, useValue: 'http://127.0.0.1:8081' },
      { provide: PUBLIC_IMAGE_INSPECTOR, useValue: inspectPublicImage },
    { provide: ScansService, inject: [LedgerStore, OciResolver, PUBLIC_IMAGE_INSPECTOR],
      useFactory: (ledger: LedgerStore, resolver: OciResolver, inspect: PublicImageInspector) =>
        new PublicImageScansService(ledger, resolver, inspect, localDbTrustAnchorFromEnv()) }] })
export class PublicImageModule {}

// Reuse the existing bounded history intake; no runtime/host routes are imported.
export function configurePublicImageIngress(app: NestExpressApplication): void {
  registerHistoryIngress(app);
  app.useBodyParser('json');
  app.useBodyParser('urlencoded', { extended: true });
}
