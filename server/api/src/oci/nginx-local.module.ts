import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { LedgerModule } from '../ledger/ledger.module.js';
import { LedgerStore } from '../ledger/ledger-store.js';
import { SecurityModule } from '../security/security.module.js';
import { OciModule } from './oci.module.js';
import { OciResolver } from './oci-resolver.js';
import { ScansController } from '../scans/scans.controller.js';
import { BrowserScansController } from '../scans/browser-scans.controller.js';
import { ScansService } from '../scans/scans.service.js';
import { NginxLocalScansService } from './nginx-local-profile.js';
import { LlmController } from '../llm/llm.controller.js';
import { BrowserIdentity } from '../llm/browser-identity.js';
import { ReportReader } from '../llm/report-context.js';
import { LlmRuntime, LlmService } from '../llm/llm.service.js';
import { llmExceptionProvider } from '../llm/llm-exception.filter.js';
import { LlmQuotaRuntime } from '../llm/quota-runtime.js';
import { RuntimeApiModule } from '../runtime/runtime-api.module.js';

@Module({ imports: [AuthModule, LedgerModule, SecurityModule, OciModule, RuntimeApiModule],
  controllers: [ScansController, BrowserScansController, LlmController],
  // LlmModule imports the default ScansModule; compose here to retain one LOCAL service.
  providers: [BrowserIdentity, ReportReader, LlmRuntime, LlmService, LlmQuotaRuntime, llmExceptionProvider,
    { provide: ScansService, inject: [LedgerStore, OciResolver],
    useFactory: (ledger: LedgerStore, resolver: OciResolver) => new NginxLocalScansService(ledger, resolver) }] })
export class NginxLocalModule {}
