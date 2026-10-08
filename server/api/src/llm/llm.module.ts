import { Module } from '@nestjs/common';
import { AuthModule } from '../auth/auth.module.js';
import { ScansModule } from '../scans/scans.module.js';
import { BrowserIdentity } from './browser-identity.js';
import { LlmController } from './llm.controller.js';
import { LlmRuntime, LlmService } from './llm.service.js';
import { ReportReader } from './report-context.js';
import { llmExceptionProvider } from './llm-exception.filter.js';
import { LlmQuotaRuntime } from './quota-runtime.js';

@Module({ imports: [AuthModule, ScansModule], controllers: [LlmController], providers: [BrowserIdentity, ReportReader, LlmRuntime, LlmService, LlmQuotaRuntime, llmExceptionProvider] })
export class LlmModule {}
