import { Module } from '@nestjs/common';
import { ScansModule } from './scans/scans.module.js';
import { AuthModule } from './auth/auth.module.js';
import { LlmModule } from './llm/llm.module.js';
import { RuntimeApiModule } from './runtime/runtime-api.module.js';

@Module({ imports: [ScansModule, AuthModule, LlmModule, RuntimeApiModule] })
export class AppModule {}
