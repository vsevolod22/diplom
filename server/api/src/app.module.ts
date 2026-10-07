import { Module } from '@nestjs/common';
import { ScansModule } from './scans/scans.module.js';
import { AuthModule } from './auth/auth.module.js';
import { LlmModule } from './llm/llm.module.js';

@Module({ imports: [ScansModule, AuthModule, LlmModule] })
export class AppModule {}
